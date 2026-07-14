---
name: rcu-mutation
description: Correct discipline for mutating an RCU / lock-free pointer-based data structure (trie, tree, list, graph) that has concurrent readers — build a new node cluster invisibly, publish it, then reclaim the old nodes after a grace period. Use when writing or reviewing any mutator on a structure read concurrently under RCU (or any publish/consume scheme), especially one with allocation-failure paths.
---

# RCU mutation: build-invisible → publish → reclaim

The safe shape for a structural mutation with concurrent RCU readers is three
phases. Get the phase boundaries right and most correctness questions dissolve.

## The three phases

1. **Build (may fail).** Allocate and fully wire the *new* node cluster. Touch
   only new nodes and their fields. The cluster must be reachable by a
   concurrent reader from **neither** direction (see "Observability"). On
   allocation failure, free the new nodes **immediately** (they were never
   observable — no grace period) and return; the old structure is untouched, so
   there is **nothing to roll back**.
2. **Publish (must not fail).** With the cluster fully built, perform the
   minimal set of stores that link it into the live structure. After the first
   such store the cluster is observable, so no failure is permitted past this
   point — do all fallible work (allocations) in phase 1.
3. **Reclaim.** Free the *old* nodes, **deferred** (call_rcu / synchronize_rcu /
   grace period). They were observable, so a reader may still hold a reference.

## Observability — the core concept

A node is **observable** the moment a concurrent reader can reach it from the
roots. Enumerate *every* channel readers traverse; in a doubly-linked structure
there are usually two:

- **Forward**: a reachable node's child/next slot points to it (the descent).
- **Backward**: a reachable node's parent/prev back-pointer points to it, *if
  readers follow back-pointers* (up-walks, ordered traversal, lazy node
  recovery from a compressed/skip encoding).
- **Sideways**: a secondary reader-traversable index — an ordered sibling/cell
  list, a hash chain, a cached min/max endpoint — that reaches the node
  independently of the tree. Each such index is its own channel: a node is
  observable while **any** channel can reach it, and "unreachable through the
  tree" proves nothing about the index.

A write **publishes** (crosses into observable) the instant it links a new node
into **any** channel of an **already-reachable** node. Writes that only touch
a brand-new node's own fields, or links *between* new nodes, are **internal /
non-observable** — do as many of those as you like in phase 1.

The classic trap: a line that looks like "set up the new node" is actually a
publish because its target is a reachable node. E.g. `set_parent(old_child,
new_node)` publishes `new_node` through the back channel, because `old_child` is
still reachable via the old structure.

## Rules that fall out

- **Never reclaim a node that became observable without a grace period.** And
  never make a node observable during phase 1 only to free it on the error path
  — that needs a grace period *and* leans on fragile reader-side consistency
  heuristics during the window. Keep the build invisible instead.
- **In phase 1, wire back-pointers directly from the pointers you hold.** Do NOT
  recover a cluster node via the *read-side* recovery machinery (the same code a
  reader uses to chase a back-pointer / decode a compressed pointer). During the
  build that machinery follows a back-pointer that still points at the *old*
  structure, so it returns the wrong node and you corrupt it. The mutator holds
  every new node directly — use that, not recovery.
- **Track / free cluster nodes by an identity that does NOT need recovery.**
  This is the same rule applied to the abort path. If your scheme has an
  encoding that resolves a node *via a back-pointer* (a skip/indirect pointer
  recovered through its child's parent link), do not record cluster nodes in
  that encoded form: the abort/free walk will resolve each tracked node to free
  it, and that back-pointer is still deferred (stale) → it resolves to the
  *wrong, live* node and frees it. Track the direct/plain form; if the published
  slot wants the encoded form, write the encoded value into the (still-private)
  slot just before publish, but keep the tracking/free/back-pointer-record in
  the plain form. (Builder helpers should therefore *return* the plain flag and
  let the caller re-encode the slot, not return the encoded one.)
- **Publish ordering matters for reader consistency** (not for failure). Publish
  the channel that stops readers from reaching about-to-be-freed nodes *first*.
  (In a re-parent: set the surviving child's new back-pointer before swinging
  the top forward slot, so an up-walk from that child enters the new cluster
  before the new cluster becomes forward-reachable and the old node is freed.)
  The brief 2-store window between is the normal mutation window your readers'
  retry/validate logic already handles.
- **When several children's back-pointers are deferred together, wire them
  fresh-before-live.** A cluster-leaf (see the realloc rule below) defers *all*
  its children's back-pointers to publish, and those children are often a mix of
  *fresh* (new, reachable only through the cluster) and *live* (re-parented from
  the old structure). Setting a **live** child's back-pointer *is itself the
  back-channel publish*: the instant it lands, a reader up-walking from that
  still-reachable child enters the cluster and can scan the cluster's *other*
  slots — including fresh siblings. So wire the cluster's own upward link and
  every **fresh** child's back-pointer **first**, and the **live** re-parent edge
  **last** (immediately before the forward publish). Backwards, a reader enters
  via the live edge and reaches a fresh sibling whose parent is not yet set —
  and this is **not** a transient window the reader retries past: the reader's
  data-dependency (consume) chain is *anchored* at the live back-pointer it
  loaded, so a fresh-parent store sequenced *after* that load has **no
  release-consume edge** to the reader. It observes the stale (often NULL) parent
  at *any* later wall-clock time. (Diagnosing exactly this — a parent set
  microseconds earlier yet read NULL — is the worked example in the
  lttng-tracing-root-cause-analysis skill. The single-surviving-child re-parent
  in the rule above is the degenerate case with no fresh siblings to strand.)
- **Commit every reader channel in one publish — a secondary index is a
  channel.** If readers also traverse a secondary index (ordered cell list,
  hash chain), the structural publish and the index splice/unsplice are ONE
  logical publication. Publishing the structure first opens a window where a
  reader finds the new node by exact lookup, then steps through its
  not-yet-spliced index entry — NULL links read as end-of-list, which is
  neither the pre- nor the post-state. Symmetrically, freeing an index entry
  whose *neighbours'* stale links still reference it is a use-after-free even
  when the node itself is unreachable through the tree (the tree is not the
  only channel). Either fold the index edges into the same atomic commit (one
  flip covering forward edge + index links), or make the reader fast path
  detect a not-yet-spliced entry (e.g. NULL link but not the cached tail) and
  fall back to the structural walk. A guard on the *writer's* own fast path
  does not protect concurrent readers.
- **Every reader-visible publish goes through the release-store primitive
  (rcu_assign_pointer) — including out-param helpers.** A helper that returns
  its result through a caller-supplied slot pointer (`*slotp = new`) performs
  an unordered publish whenever a caller passes a LIVE slot (a child slot of a
  published parent, the root) instead of a local. Either use
  rcu_assign_pointer unconditionally in the helper (harmless when the slot is
  a local), or forbid live slots in the helper's contract and make every
  caller re-publish with the release store. Audit out-param helpers by call
  site: the one caller that passes a live slot turns a correct helper into a
  plain-store publication with no ordering against the node-body stores.
- **The old nodes stay allocated and coherent through phases 1 and 2.** They are
  serving readers the whole time. Free only in phase 3.
- **An "exclusive / no-readers" mode flips deferred reclaim to synchronous —
  re-check every safety argument built on the grace period.** Code whose
  correctness argument is "the old copy stays allocated until a grace period
  elapses" (a relocation pass navigating from old copies, an undo walk back
  through possibly-freed ancestors, draining a detached subtree) silently
  becomes a use-after-free when the structure is in exclusive mode and frees
  happen immediately. The dual obligation: never mark a structure exclusive —
  or return it to a caller as exclusive — on a path that skipped the reader
  drain; every path that can leave a parked reader inside must synchronize
  first, not just the common one.
- **A node that may be reallocated mid-build defers ALL its children's
  back-pointers — no per-child exception.** If your structure grows/shrinks a
  node by *reallocating* it (resize, recompact, rebalance creates a new copy and
  re-parents the children it copied), then a live child whose back-pointer you
  set "directly" still gets re-published to each successive copy by that
  re-parent step — and left dangling if a later allocation frees the copy. So at
  a *cluster-leaf* (a new node at the cluster's lower boundary, whose children
  include live nodes), set **no** child's back-pointer during the build, not even
  the children that look new/safe; wire them all at publish, using the node's
  **final** identity (track it across reallocations — the caller always gets the
  new flag back). Selective deferral is the trap: inserting a *sibling* child
  reallocates the node and re-parents the one you thought you'd deferred. (A
  boolean "this target is a cluster-leaf, skip its whole re-parent step" is
  cleaner and order-independent than a per-child "defer this one" flag, which
  would force you to add the deferred child last.)
- **Clear a freshly-built node's parent/back-link metadata before you grow
  (reallocate) it.** If you build a new node and then add another child that
  triggers a realloc, the realloc copies the *old* node's parent (and any
  back-link slot it derives from it) into the new copy — and may write *through*
  that inherited parent to update its forward slot. A fresh node from a recycled
  allocation can carry stale, non-NULL parent metadata, so that inherited write
  lands on an unrelated live node. The new node has no parent until you wire it
  at publish; zero its parent/back-link fields before the growing step.

## Anti-patterns (and why)

- **Mutate-in-place then roll back on error.** Tempting and localized, but if the
  mutated pointer was observable, rollback alone is a use-after-free (a reader
  grabbed the transient target); you must add a grace period before freeing, and
  the in-window correctness depends on a reader-side heuristic (e.g. "the lengths
  won't match so the reader retries") that is an emergent, non-local invariant,
  not a guarantee. Prefer build-invisible: there is no window and nothing to roll
  back.
- **Using the published-tree insert/link API to wire an unpublished cluster.**
  Those APIs set back-pointers via read-side recovery (see the rule above) and
  assume the slot is already consistent. Wire the cluster with direct field
  stores.

## Composing build-invisible steps into a transaction

A build-invisible step is only as safe as the transaction around it.

- **Propagate the step's failure; don't let a dispatch layer swallow it.** When a
  descent/dispatch routine calls your mutation and treats its allocation failure
  like an ordinary "stop" (e.g. returns the same "done" signal on both success
  and OOM), the caller proceeds on un-built / stale state and corrupts the
  structure anyway — the build-invisible step's clean OOM is wasted. Thread the
  failure out and abort the whole transaction *before any irreversible publish*
  (before the point of no return, so there is nothing to roll back). A
  `(void)`-cast or ignored return on a fallible mutation is a red flag.
- **Never publish an incomplete intermediate that a later, fallible step
  completes.** A transaction that publishes a deliberately-partial structure
  (e.g. a branch holding one of its eventual two children, meant to be finished
  by a subsequent *allocating* step) is **not atomic**: an OOM in the later step
  leaves the partial structure live — often a verify-invalid / non-canonical node
  rather than a dangling pointer, so it's a subtler corruption that exact lookups
  miss. Either build the *whole* cluster (every step's output) invisibly and
  publish once, or accept that the later step's failure must roll back the
  earlier publish — usually impractical once the replaced node is freed. If you
  can only fix the first step now, say so explicitly and scope the
  transaction-atomicity of the rest as separate work.
- **Error paths must report failure faithfully and reset out-params.** Mapping
  an allocation failure to a benign status (NOT_FOUND, or a "duplicate found"
  success) tells the caller the operation didn't happen — or worse, that it
  did. And if an out-param was set optimistically *before* the fallible step
  (e.g. `*result = removed chain`, under a contract of "caller reclaims it
  after a grace period"), the error path MUST reset it to NULL: a caller that
  keys reclamation off the non-NULL out-param frees live data. Decide each
  error exit's (status, out-params, structure state) triple together; an error
  status paired with a success-shaped out-param is as dangerous as the
  reverse. Where a distinct out-of-memory status exists, use it — the caller's
  retry decision depends on distinguishing "absent" from "failed".

## Worked example (userspace-rcu fractal trie compressed-split)

Splitting compressed node `cn`("ABCDE", child `C`) under parent `P` on insert of
"ABXYZ": build cluster `P→(skip "AB")→branch{ 'C'→sfx"DE"→C , 'X'→nb"YZ"→leaf }`.

- Phase 1: alloc sfx/nb/branch/prefix; wire forward slots and set every *new*
  node's back-pointer **directly**; set the `branch→sfx` slot to its final skip
  value even though it only becomes *recoverable* once `C->parent` flips — no
  reader sees it yet, and the mutator never recovers through it. Never touch `C`
  or `P`'s slot. (Install sfx with its *plain* flag so the API recovers it
  directly, then overwrite the slot with the skip value — never install the skip
  flag, which would recover sfx through `C->parent` = still `cn`.)
- OOM in phase 1: free sfx/nb/branch/prefix immediately; `C`, `cn`, `P` untouched.
- Phase 2: `C->parent = sfx` (back), then `P.slot = skip(branch,2)` (forward).
- Phase 3: free `cn` deferred.

"Skip-encoded" is a *publication* property: a skip pointer encodes the
compressed node's *child* + length and recovers the node via that child's
back-pointer, so it only resolves once that back-pointer is published. Setting
the value early in an unobserved slot is fine; resolving it is a reader concern.
