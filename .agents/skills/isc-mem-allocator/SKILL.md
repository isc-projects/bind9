---
name: isc-mem-allocator
description: BIND 9's memory allocator wrapper (isc_mem memory contexts and isc_mempool fixed-size pools). Use when writing or reviewing code that allocates/frees memory anywhere in BIND 9, when choosing between isc_mem_get/put and isc_mem_allocate/free, when debugging "isc_mem_inuse(ctx) == 0" or mempool-leak assertion failures, memory-leak reports, overmem/water-mark behavior, or ISC_MEM_DEBUG* tracing.
---

# BIND 9 allocator wrapper (isc_mem / isc_mempool)

Source of truth: `lib/isc/include/isc/mem.h` (public API), `lib/isc/mem.c`
(implementation), `lib/isc/mem_p.h` (private init/shutdown),
`lib/isc/jemalloc_shim.h` (non-jemalloc fallback).

## Big picture

`isc_mem_t` (an "mctx") is a thin, reference-counted accounting wrapper over
jemalloc's non-standard API: `mallocx` / `sdallocx` / `rallocx` / `sallocx`.
On systems without jemalloc, `jemalloc_shim.h` emulates those on top of
`malloc`, recovering sizes from `malloc_usable_size()` / `malloc_size()`, or
as a last resort by prepending a `size_info` header to every allocation.

Key consequences:

- **Allocation never fails.** OOM calls `oom()`, which writes a
  signal-safe report + backtrace to stderr and `abort()`s. Never write
  `if (ptr == NULL)` after an `isc_mem_*` call; there is no NULL return.
- **Deallocation is size-hinted** (`sdallocx`). Freeing with the wrong size
  is undefined behavior inside jemalloc, not just a stats bug.
- All contexts share jemalloc arenas (`jemalloc_flags` is currently always 0),
  so an mctx is an *accounting domain*, not a heap: it tracks who owes what,
  it does not partition memory.
- A global default context `isc_g_mctx` always exists (created by the library
  constructor `isc__lib_initialize()` → `isc__mem_initialize()` in
  `lib/isc/lib.c`). Use it only when nothing more specific fits.

## The two allocation families — never mix them

| | sized family | usable-size family |
|---|---|---|
| alloc | `isc_mem_get(mctx, size)` | `isc_mem_allocate(mctx, size)` |
| zeroed | `isc_mem_cget(mctx, n, size)` | `isc_mem_callocate(mctx, n, size)` |
| realloc | `isc_mem_reget(mctx, p, oldsize, newsize)` / `isc_mem_creget(mctx, p, oldn, newn, size)` | `isc_mem_reallocate(mctx, p, newsize)` |
| free | `isc_mem_put(mctx, p, size)` / `isc_mem_cput(mctx, p, n, size)` | `isc_mem_free(mctx, p)` |
| strdup | — | `isc_mem_strdup(mctx, s)` |
| stats charge | the size you passed | real usable size via `sallocx` (≥ requested) |

Rules:

- Memory from `isc_mem_get` **must** be returned with `isc_mem_put` using the
  **same mctx and the same size**. Memory from `isc_mem_allocate` must go back
  via `isc_mem_free`. Crossing the families corrupts the per-context `inuse`
  counter (put charges the requested size, free charges the `sallocx` size),
  which detonates later as `INSIST(isc_mem_inuse(ctx) == 0)` when the context
  is destroyed. The header's `ISC_ATTR_MALLOC_DEALLOCATOR_IDX` attributes make
  compilers warn about some mismatches — treat those warnings as errors.
- Prefer the sized family whenever the caller knows the size (the common case:
  `isc_mem_get(mctx, sizeof(*obj))`). Use allocate/free only for
  variable-length data whose size is inconvenient to carry around.
- The `c`-prefixed variants are calloc-alikes: `ISC_CHECKED_MUL(n, size)`
  (overflow-fatal multiply) plus `ISC__MEM_ZERO`. `ISC__MEM_ZERO` is verbatim
  jemalloc's `MALLOCX_ZERO` (0x40), RUNTIME_CHECKed at startup. Free a cget'd
  array with `isc_mem_cput(mctx, p, n, size)` so the sizes match.
- Size 0 is legal and symmetric: both get and put bump 0 to
  `sizeof(void *)` (`ADJUST_ZERO_ALLOCATION_SIZE`).

### The put/free macros NULL the pointer

`isc_mem_put`, `isc_mem_cput`, `isc_mem_free`, `isc_mem_putanddetach`, and
`isc_mempool_put` are statement macros that end with `(p) = NULL;`. So:

- The pointer argument must be an assignable lvalue and must not have side
  effects (macro arguments are expanded more than once — never
  `isc_mem_put(mctx, arr[i++], size)`).
- After the call the variable is NULL — code relying on the old pointer value
  afterwards is a bug even though the memory "was just there".

### isc_mem_putanddetach

For objects that hold a reference to their own mctx:

```c
isc_mem_putanddetach(&obj->mctx, obj, sizeof(*obj));
```

frees `obj` and then drops the mctx reference in the safe order (equivalent to
attach-to-local / detach-member / put / detach-local). This is the standard
destructor idiom; use it instead of an open-coded put + detach.

## Context lifecycle

- `isc_mem_create("name", &mctx)` — name is mandatory, copied, shows up in
  stats channel output and leak dumps. (The create macro also re-assigns
  `isc__mem_malloc = mallocx`; that is a deliberate link-order hack for
  jemalloc — see jemalloc issue #2566 — don't "clean it up".)
- Refcounted via `ISC_REFCOUNT_IMPL`: `isc_mem_attach(src, &dst)`,
  `isc_mem_detach(&mctx)` (NULLs the pointer), `isc_mem_ref/unref`. The last
  detach destroys the context.
- Destruction asserts the books balance: `INSIST(isc_mem_inuse(ctx) == 0)` and
  that no pools remain. `isc_mem_setdestroycheck(mctx, false)` disables the
  leak check — almost never the right fix; a failing inuse INSIST means a leak
  or a family/size mismatch.
- `isc_mem_checkdestroyed(stderr)` (called by named/tests at shutdown) arms a
  library-shutdown check that *every* context was destroyed; it hits
  `UNREACHABLE()` otherwise, after dumping live contexts when debugging is on.
- `isc__mem_shutdown()` runs `rcu_barrier()` before checking, so RCU-deferred
  frees (call_rcu) are flushed first — deferred frees still count as live
  until the grace period runs.

## Statistics and accounting internals

- `inuse` is striped per thread id: `stat_s[ISC_TID_MAX + 1]` cacheline-padded
  slots; `ctx->stat = &stat_s[1]` so `isc_tid()` == -1 (ISC_TID_UNKNOWN,
  i.e. threads outside the loopmgr) indexes `stat[-1]` legally.
  Updates are relaxed atomics on the caller's own stripe.
- A stripe can go **negative** (thread A frees what thread B allocated) —
  that's why stripes are signed. Only the sum (`isc_mem_inuse()`, which walks
  -1..isc_tid_count()) is meaningful.
- `isc_mem_inuse()` is O(threads) and iterates all stripes — fine for
  water-mark checks, don't put it in per-packet hot paths gratuitously.

### Water marks / overmem

- `isc_mem_setwater(mctx, hiwater, lowater)` (0,0 or `isc_mem_clearwater()`
  disables). Used by the resolver/cache to bound cache memory.
- `isc_mem_isovermem()` is **probabilistic**: false below lowater, true above
  hiwater, and in between returns true with probability ramping linearly
  0→1 (8-bit resolution, `isc_random8()`). This deliberately spreads cache
  cleaning over many inserts instead of a thundering herd at the mark —
  do not "fix" the randomness, and don't expect two consecutive calls to
  agree.

### Returning memory to the OS

- Each thread counts bytes it frees (`freed_bytes`, thread-local); every
  16 MiB it triggers `mem_purge()`: jemalloc `arena.<all>.decay` (or glibc
  `malloc_trim(0)`), rate-limited via CAS on `last_purge` to once per second
  globally.
- Init-time jemalloc tuning: `background_thread = true`,
  `dirty_decay_ms = 10000` applied to existing and future arenas. Failures
  are ignored on purpose (the volumetric purge covers it).

## Debugging facilities

Compile-time gate: `ISC_MEM_TRACKLINES` (set automatically by
`-Ddeveloper=enabled` meson builds) compiles in per-call
`__func__/__FILE__/__LINE__` plumbing. Without it, the runtime flags below are
inert no-ops. `ISC_MEM_TRACE` additionally turns attach/detach into traced
refcounting.

Runtime flags (a context copies the global default at creation;
`isc_mem_debugon()/debugoff()` adjust the default *and* `isc_g_mctx`;
`isc_mem_setdebugging()` sets one context but requires `inuse == 0`):

- `ISC_MEM_DEBUGTRACE` — print every alloc/free (`add ptr size func file
  line mctx` / `del ...`) to stderr.
- `ISC_MEM_DEBUGRECORD` — record every live allocation in a 512-bucket hash
  table; freeing something never allocated hits `UNREACHABLE()`; leaks are
  dumped (`print_active`) with file:line when the context is destroyed. This
  is the tool for "inuse != 0 at destroy" hunts.
- `ISC_MEM_DEBUGUSAGE` — log when usage crosses the water marks.

Each flag can be enabled by simply **setting the environment variable of the
same name** (existence is checked, not the value) before start; the file
name in each record is copied, not pointed to, so plugins can be unloaded
safely.

Observability: `isc_mem_stats(mctx, fp)` (pool table + active allocations),
`isc__mem_printactive()` (unit tests), and the statistics channel renders all
contexts via `isc_mem_renderxml()` / `isc_mem_renderjson()` (id, name,
references, inuse, pool count, water marks).

## isc_mempool — fixed-size free-list pools

`isc_mempool_t` batches fixed-size items on top of an mctx to cut allocator
round-trips (used for message buffers etc.):

```c
isc_mempool_create(mctx, sizeof(item_t), "items", &pool);
isc_mempool_setfillcount(pool, 32);  /* items grabbed per refill, default 1 */
isc_mempool_setfreemax(pool, 32);    /* free-list cap, default 1 */
...
item_t *it = isc_mempool_get(pool);   /* never NULL */
isc_mempool_put(pool, it);            /* NULLs 'it' */
...
isc_mempool_destroy(&pool);
```

Critical facts:

- **No locking whatsoever.** The struct comment says "always unlocked"; the
  caller must confine a pool to one thread or provide external locking.
  Getters (`getallocated`, `getfreecount`, ...) return garbage under
  concurrent mutation.
- `get`: pops the free list; if empty, grabs `fillcount` items from the mctx
  in one loop. `put`: pushes back on the free list unless `freecount >=
  freemax`, in which case the item goes straight back to the mctx.
- Item size is silently raised to `sizeof(element)` (one pointer) because
  free items are chained through their own storage — a pool of very small
  items wastes the difference.
- Under AddressSanitizer, `fillcount` is forced to 1 and `freemax` to 0 so
  every get/put reaches the real allocator and poisoning/use-after-free
  detection works. Don't assume pooling behavior in ASAN builds.
- `isc_mempool_destroy()` requires every item returned: outstanding items log
  `UNEXPECTED_ERROR("mempool %s leaked memory")` and fail a REQUIRE.
- The pool holds a reference on its mctx and is linked on the context's
  `pools` list (`isc_mem_stats` prints them); a context cannot be destroyed
  while its pools exist.
- Pool items are charged to the mctx when fetched from it (i.e. items sitting
  on the pool free list still count as inuse for the mctx).

## Review checklist

When touching allocation code, check:

1. get↔put / allocate↔free pairing, same mctx, same size (or matched
   `n, size` pairs for cget/cput). Grep for the struct's free sites when a
   size or family changes.
2. Realloc sizing: `isc_mem_reget` needs the *correct old size*; on the
   non-jemalloc path it manually zeroes the growth for `creget`, so a wrong
   old size also breaks zeroing.
3. No NULL checks / error paths after allocation — remove dead OOM handling.
4. Put-macro arguments: lvalue, no side effects, and nothing reads the
   pointer after the macro (it's NULL now).
5. Destructor idiom: last-ref objects use `isc_mem_putanddetach`.
6. Mempools: single-thread confinement is actually guaranteed; destroy path
   returns every item first.
7. New long-lived subsystems get their own named mctx (visible in stats
   channel), not `isc_g_mctx`.
