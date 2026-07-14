---
name: lttng-tracing-root-cause-analysis
description: 'Methodology for root-causing hard concurrency / memory-ordering bugs (intermittent races, use-after-free, RCU/lock-free publish-order defects, "impossible" stale reads) with LTTng flight-recorder (snapshot) tracing — when static analysis, printf, and a debugger all fall short. Covers the snapshot+violation+abort setup, tracepoint instrumentation discipline (why tracepoints not printf), how to enrich a violation event so the trace is self-diagnosing, and the trace-reading patterns that crack these bugs (notably: a stale-after-write "paradox" is a happens-before gap, not a timing bug).'
---

# LTTng flight-recorder root-cause analysis

When a concurrency bug is intermittent and the assertion fires deep in a
hot path, the three usual tools fail in three different ways:

- **Static reading** can't tell you the *interleaving* that actually happened.
- **printf** perturbs the timing — the µs-scale window you're hunting often
  vanishes when you add I/O — and floods you with output from the wrong threads.
- **A debugger** stops the world; the race won't reproduce under a breakpoint,
  and you can't single-step a 192-thread interleaving.

LTTng flight-recorder (snapshot) mode is the tool that fits: near-zero overhead
ring buffers per CPU, a global high-resolution clock so events from different
CPUs are comparable, and an on-demand dump of exactly the window leading up to
the failure. You instrument the *culprit* to fire a violation tracepoint, dump
the snapshot, and abort; then you read the last events before the abort and the
interleaving walks you to the cause. This is the tool of last resort for
concurrency bugs — reach for it once you've ruled out the cheap explanations.

## The setup: snapshot + violation + abort

1. **Flight-recorder (snapshot) session, small per-CPU buffers.** Snapshot mode
   keeps a rolling overwrite buffer in memory and only writes to disk when you
   ask. Start small so the dump is a tight window around the failure:

   ```
   lttng create mysess --snapshot
   lttng enable-channel --userspace --subbuf-size=64K --num-subbuf=4 ch
   lttng enable-event   --userspace --channel ch 'myprovider:*'
   lttng start
   ```

   64 KiB/CPU is the CLAUDE.md default, and small is right for two reasons,
   not one: (a) the dump is a tight window around the failure, so it decodes
   fast and you read only the relevant events; (b) — the one that actually
   matters for *reproducing* the bug — a 64 KiB ring stays resident in L2, so
   the tracepoint stores don't evict the working set into L3/DRAM. A large
   (multi-MiB) ring pollutes the cache and perturbs the very µs-scale race
   window you're hunting; the bug can stop reproducing under heavy tracing for
   the same reason it stops under printf. Keep the ring small to keep the
   timing faithful. If your per-step tracepoints (below) are high-rate and the
   interesting window scrolls out before the violation, FIRST cut the event
   rate — disable the flooding per-iteration event and recover its data another
   way (e.g. from a core, or a single enriched violation event) — and only bump
   the subbuf size as a last resort (e.g. 256K × 4 = 1 MiB/CPU), as little as
   you need; a bigger buffer means both more events to read and more timing
   disturbance.

2. **Emit the violation from the culprit, then snapshot, then abort.** At the
   exact check that detects the corruption, fire an enriched tracepoint, persist
   the in-memory ring, and crash so nothing overwrites the window:

   ```c
   if (corruption_detected) {
       FT_TP(violation, /* discriminating state — see below */);
       (void) system("lttng snapshot record 1>&2");
       abort();
   }
   ```

   Gate all of this behind a build flag (e.g. `-DFT_ENABLE_TRACING`) so it
   compiles out of production and your normal test matrix.

3. **Read the window:**

   ```
   lttng stop
   babeltrace2 ~/lttng-traces/mysess-*/ > trace.txt
   ```

## Instrumentation discipline

- **Tracepoints, never printf — timing matters.** The bug lives in a
  sub-microsecond window; printf's I/O perturbs it out of existence and serializes
  threads. Tracepoint emission is a few hundred ns into a lock-free per-CPU buffer.

- **Make the violation event self-diagnosing.** Don't just record "it failed" —
  record the state that *discriminates between hypotheses*. For a bad pointer,
  the high-value fields are usually:
  - the object's identity *and* a **round-trip check** (e.g. resolve the object
    by its own back-reference and compare): if it round-trips to itself the
    object is valid; if not, it's **recycled / stale memory**. This one field
    instantly separates "use-after-free of recycled memory" from "valid object,
    wrong links."
  - liveness counters (child count, refcount): zero/garbage ⇒ freed.
  - the relevant back-pointers (parent, prev) so you can see which links were
    and weren't wired.

  These let you classify the failure from the violation event alone, before you
  even read the surrounding window.

- **Add enter/step tracepoints to follow the algorithm.** One tracepoint at the
  entry of the suspect routine and one per iteration of its core loop (carrying
  the loop variables) reconstruct the control flow that reached the violation —
  you see the *path*, not just the endpoint.

- **Mind the `LTTNG_UST_TP_ARGS` limit.** lttng-ust caps a tracepoint at ~10
  argument pairs. Exceed it and you get a cryptic macro error like
  `unknown type name 'LTTNG_UST__TP_EXPROTOconst'` (the arg-count machinery ran
  off the end). Keep a violation event ≤ ~8 fields; drop redundant ones (e.g. a
  field that's always NULL at the violation, or one a round-trip already
  implies). Pointer fields use `lttng_ust_field_integer_hex(uintptr_t, name,
  (uintptr_t) val)`; counters use `lttng_ust_field_integer(...)`.

## Reading the trace — the patterns that crack it

- **Read the full window, all CPUs, with ns timestamps and raw addresses.**
  Then **grep by address** to pull every event touching the culprit object(s)
  across all threads, in time order. This reconstructs the cross-thread
  interleaving that no static reading could show. Note the `cpu_id` on each
  event to separate the writer thread from the reader thread.

- **Distinguish trace *markers* from the actual memory operation.** A tracepoint
  at a function's entry fires *before* the store inside it. Don't read the
  tracepoint timestamp as the store's timestamp — find the event that
  corresponds to the *real* `rcu_assign` / publish (often a different,
  later marker). Mis-attributing the store's time sends you chasing ghosts.

- **THE key pattern — the stale-after-write "paradox" is a happens-before gap,
  not a timing bug.** If the trace shows a field *written* at time T and *read
  stale* at T+Δ on the **same object** with **no intervening write anywhere**,
  that is not a contradiction and not "the store didn't land yet" (Δ can be
  microseconds). It means the reader reached that field through a pointer that
  was **published before the field's store**, so there is **no release-consume
  edge** carrying the store to the reader — the stale read is legal at *any*
  wall-clock delta. Treat the paradox as a signal: find which *earlier* publish
  anchored the reader's data-dependency (consume) chain, and you've found the
  mis-ordered publish. The fix is to publish the field **before** the pointer
  that lets readers reach it (see the `rcu-mutation` skill: wire back-pointers
  before the forward/back-channel publish; fresh edges before the live
  re-parent edge).

- **Walk backwards from the abort.** The violation event is the last thing in
  the buffer. The few events just before it — on *any* CPU — are the proximate
  cause. Follow the addresses upward until the picture is consistent.

## After you've found it

- Strip the temporary enter/step/violation tracepoints and the
  `system("lttng snapshot record")` + `abort()` from the code before committing
  (they were scaffolding; the build flag kept them out of the matrix, but don't
  leave dead diagnostic noise in the source). Keep the durable, low-rate
  tracepoints if they have ongoing value.
- A correct invariant you *discovered* while instrumenting may deserve to become
  a permanent assertion / verify-pass — but only commit it once the code
  actually satisfies it, or it turns the tree red on a pre-existing,
  non-destructive gap (scope it as separate work).

## Worked example (userspace-rcu fractal trie — `holder != NULL`)

Symptom: an ordered-traversal reader intermittently hit `assert(holder != NULL)`
in an up-walk (`ft_skip_reanchor`) under empty→rebuild churn — ~88% repro, but
no static reading found it.

1. Added a `reanchor_violation` tracepoint (the reached node, a **round-trip**
   `metadata_to_item` check, its child count, and the relevant back-pointers) +
   `reanchor_enter`/`reanchor_step` to follow the up-walk, all behind
   `-DFT_ENABLE_TRACING`; snapshot + abort on the violation.

2. The violation event alone said: round-trip == self (so **valid, not
   recycled**), child-count == 1 (**live**), back-pointer set — yet `parent ==
   NULL`. So: a valid, live node, reachable, with an unwired parent.

3. The paradox: the writer set that node's `parent` at T, the reader read NULL
   at T+2.3µs, same metadata object, no intervening write. → happens-before gap.

4. The full window (grepping the node's address across CPUs) showed the writer
   publishing a recompacted cluster into the live tree by setting a **live**
   re-parented child's back-pointer (a back-channel publish) **before** wiring a
   **fresh** sibling child's parent. The reader entered via the live child, so
   its consume chain anchored *before* the fresh-parent store → legal stale NULL.

5. Fix: at publish, wire the fresh edge (and the cluster top's own back-pointer)
   first and the live re-parent edge last. ~88% failure → 0/96.

LTTng didn't just confirm a hypothesis — the enriched violation event and the
all-CPU window *generated* the explanation that static analysis had missed.
