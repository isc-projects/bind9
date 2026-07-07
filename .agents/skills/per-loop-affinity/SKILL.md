---
name: per-loop-affinity
description: Design pattern for per-loop (per-thread) sharded data structures in BIND 9 — isc_tid() affinity replaces locking, foreign mutation becomes mark + owner lazy-reap, and eviction pressure must spread across shards. Use when designing or reviewing sharded LRU/SIEVE caches, per-loop lists, or any structure partitioned by loop/thread id.
---

# Per-loop affinity: ownership instead of locking

When a data structure is sharded per event-loop and each shard is owned
exclusively by its loop (`isc_tid()` affinity), the owner needs no
locking for insert/walk/unlink at all. The rules below preserve that
exclusivity; break any of them and the design degrades back to a locked
(or racy) structure.

## Ownership rules

- **Owner-only mutation and traversal.** Only the owning loop touches
  the shard's link pointers. Foreign threads never walk, unlink, or
  even *read* link pointers — peeking at them cross-thread is a data
  race (TSAN will find it), not an optimization.
- **Foreign deletion = mark + hand over, owner reaps lazily.** A
  deleter on another thread marks the entry dead (an atomic attribute)
  and hands the *exact entry* to the owner — a wait-free MPSC stack per
  shard works well; the push takes its own reference because the hint
  races the owner's eviction walk. The owner unlinks during its own
  subsequent operations, off any hot lock.
- **Never make anyone scan for marked entries.** An O(shard) sweep to
  *find* dead entries — by the owner or anyone else — degrades
  progressively as the shard grows and can collapse throughput under
  load. The handoff must carry the entry itself.
- **Gate the handoff with an atomic membership bit** (owner sets it at
  insert, clears it at every unlink path, including teardown). A stale
  bit means pushing onto a never-drained stack; a missing gate means
  double handoff.
- **The shard holds its own reference to every linked entry**, so a
  marked entry can outlive its parent object; store whatever the reaper
  needs to finish the job (e.g. a lock index) in the entry itself
  rather than reaching through pointers that may be gone.
- **Bound zombie lifetime.** If reaping only happens during eviction, a
  below-limit shard never reaps; advance a small reap cursor on each
  insert so marked entries cannot accumulate unboundedly.

## Eviction fairness across shards

- **Never drain one shard to satisfy a purge before moving to the
  next** — that degrades LRU/SIEVE to random mass-eviction of whichever
  shard was picked first. Spread the pressure: evict one entry per
  shard round-robin, or avoid sharding the eviction structure that
  finely in the first place.
- Better still, **colocate eviction capacity with insert pressure**:
  each loop evicts from its own shard, so a busy loop owns a
  proportionally bigger shard and eviction scales with the load that
  created it, by construction.

Related: the rcu-mutation skill covers the reader-visible side
(publish/reclaim discipline) of the same structures.
