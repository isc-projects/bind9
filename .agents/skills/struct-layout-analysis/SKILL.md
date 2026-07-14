---
name: struct-layout-analysis
description: Measure and fix C struct layout in BIND 9 — pahole on the build's DWARF for sizes, padding holes, and cacheline boundaries, plus the house cacheline-padding idiom. Use when asked about struct size, padding, false sharing, or when adding/reordering members in hot structures.
---

# Struct layout: measure with pahole, pad with a multiplier

## Measuring — pahole, never throwaway sizeof programs

The developer build (`-Og -ggdb`) already carries DWARF; read it
instead of compiling sizeof/offsetof snippets:

```sh
pahole -C <struct_name> build/lib/dns/libdns*.so.p/<file>.c.o
pahole --holes -C <struct_name> <object-or-binary>
```

pahole prints member offsets, padding holes, total size, and cacheline
boundaries — complete layout information the compiler already computed,
with no boilerplate to write. Any object file under `build/` or the
final binary works as input.

## Padding to cachelines — union arm with a plain multiplier

Pad a struct to a whole number of cache lines with a union arm sized by
a plain multiplier, always paired with a static assert:

```c
struct foo {
	union {
		struct {
			/* members */
		};
		uint8_t __padding[ISC_OS_CACHELINE_SIZE * 6];
	};
};
STATIC_ASSERT(sizeof(struct foo) % ISC_OS_CACHELINE_SIZE == 0,
	      "struct foo size must be a multiple of the cacheline size");
```

Pick the smallest `n` that fits; when members outgrow the arm to a
non-multiple size, the STATIC_ASSERT fires and prompts a bump of `n`.

Do NOT use the enumerated-sizeof trailing formula
`uint8_t __padding[CACHELINE - (sizeof(a) + sizeof(b) + ...) % CACHELINE]`
(the historical qpzone style): it must enumerate every member's sizeof,
so adding a member silently miscounts unless the formula is updated in
lockstep. The multiplier form has no such coupling and is easier to
read.
