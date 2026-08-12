---
name: isc-async-scheduling
description: How BIND 9 schedules callbacks — isc_job_run (same loop), isc_async_run (any thread → any loop), isc_work_enqueue (offload to a worker thread). Use when deciding where a callback should run, deferring a call to break lock re-entrancy or unwind the stack, offloading blocking/CPU work off an event loop, canceling in-flight work, or debugging "callback ran on the wrong thread", a use-after-free of a loop-owned object, or a job list corruption.
---

# Asynchronous calls in BIND 9

Three primitives schedule a callback. They are not interchangeable, and
picking the wrong one is either a data race or a stalled event loop.

| Need | Use | Runs on |
|---|---|---|
| Defer within the current loop (break lock re-entrancy, unwind the stack, re-arm) | `isc_job_run(loop, &obj->job, cb, arg)` | same loop, next iteration |
| Hand a callback to *another* loop, or schedule from a non-loop thread | `isc_async_run(loop, cb, arg)` / `isc_async_current(cb, arg)` | target loop |
| Blocking or CPU-heavy work (disk I/O, zone load/dump, crypto) | `isc_work_enqueue(loop, lane, cb, done_cb, arg)` | worker thread; `done_cb` back on the origin loop |

`isc_async_run()` is **the only thread-safe one.** Everything else — the
loop, timers, netmgr sockets, `isc_job_run()` — must be touched from the
owning loop thread only.

## isc_job_run — cheapest, same loop only

- Caller owns the `isc_job_t` storage: embed it in the object
  (`ISC_JOB_INITIALIZER`), don't heap-allocate one. No allocation, no
  atomics — an intrusive list plus a `uv_idle_t`.
- **Not thread-safe, and not checked.** There is no `REQUIRE(VALID_LOOP)`
  and no tid assertion in `isc_job_run()`; passing a foreign loop
  corrupts that loop's list silently. It trusts you.
- **One in-flight arming per `isc_job_t`.** `isc_job_run()` does
  `ISC_LINK_INIT()` right before appending, which defeats
  `ISC_LIST_APPEND()`'s `!ISC_LINK_LINKED` assertion — re-arming a job
  that is still queued corrupts `run_jobs` with no diagnostic. If one
  object can have two of these in flight, it needs two `isc_job_t`s.
- **Re-arming from inside the job's own callback is fine and is the
  intended pattern.** `isc__job_cb()` copies out `cb`/`cbarg` and unlinks
  the job *before* invoking it, so the callback may re-arm the job — or
  free the object that contains it.
- A job scheduled from within a running job does **not** run in the same
  drain; it runs on the loop's next iteration. And while any job is
  armed the idle handle keeps uv from blocking in poll — a perpetually
  self-re-arming job chain spins the loop at 100% CPU.

## isc_async_run — the thread-safe one

- Any thread → any loop, including your own (`isc_async_current()`).
  Lock-free enqueue (urcu `cds_wfcq`) plus `uv_async_send()`; the send is
  only issued on the empty→non-empty transition, and `uv_async_send()`
  coalesces anyway.
- **Always deferred, never inline** — even when the target is the current
  loop. That is exactly why netmgr routes callbacks through it: the
  caller may be holding a lock the callback wants to take. If you catch
  yourself invoking a user callback directly from a netmgr code path,
  this is the fix.
- **It takes no reference on the loop.** The caller must guarantee the
  loop outlives the callback — `isc_work` does this explicitly with
  `isc_loop_ref()`. Forgetting it is the easy use-after-free here.
- Allocates the `isc_job_t` from the *target* loop's `mctx` (fine —
  `isc_mem` is thread-safe) and frees it after the callback returns.
- Do not rely on any ordering between `isc_job_run()` and
  `isc_async_run()` callbacks. Two `isc_async_run()` calls to the same
  loop keep their order.

## isc_work_enqueue — get off the loop

- Each loop owns one worker thread **per lane**: `ISC_WORKLANE_FAST`
  (short bounded tasks, e.g. crypto — `dns_message` sig checks,
  validator) and `ISC_WORKLANE_SLOW` (blocking/long — master file
  load/dump, xfrin apply, catz/rpz updates). Keeping slow work on its own
  lane stops it from queueing behind—and delaying—fast work.
- `REQUIRE(loop == isc_loop())`: you may only enqueue onto your *own*
  loop's worker. From another thread, `isc_async_run()` to the target
  loop first, then enqueue there.
- `done_cb` always runs back on the origin loop, with whatever `cb`
  returned — that is where you touch loop-owned state again. The work
  `cb` itself runs on the worker thread and must not touch the loop.
- **A worker thread has no loop and no tid.** `workthread_thread()` never
  sets the thread-locals, so inside a work `cb` `isc_loop()` is NULL and
  `isc_tid()` is `ISC_TID_UNKNOWN` (asserted in `tests/isc/work_test.c`).
  Anything sharded by tid — see [[per-loop-affinity]] — is therefore
  unusable from a work callback; capture what you need in `cbarg` before
  enqueueing, and do the loop-side work in `done_cb`.
- **Cancellation is a tombstone, not a removal.** `isc_work_cancel()`
  CASes `QUEUED → CANCELED` and returns true only if it won that race
  (`uv_cancel` semantics). Nothing is freed, the node stays in the queue,
  and **`done_cb` still runs**, with `ISC_R_CANCELED`. The handle is
  valid only until `done_cb` has run — never afterwards. (No caller and
  no test exercises this yet; verify against `work.c` before leaning on
  it.)
- **At shutdown the work callback can run on the loop thread.** Once the
  worker's SHUTDOWN bit is set, `isc_work_enqueue()` stops queueing and
  routes `work_run` through `isc_async_run()` instead — so a "blocking"
  callback executes on the event loop. Work callbacks must tolerate that.

## Cross-cutting rules

- **Never hold `rcu_read_lock()` across a callback return.** The loop's
  `uv_prepare` (`quiescent_cb`) reaches a quiescent state and goes
  RCU-offline every iteration; non-QSBR builds assert
  `!rcu_read_ongoing()` there. Read-side sections live and die inside one
  callback.
- **Exclusive mode is genuinely exclusive.** `isc_loopmgr_pause()` parks
  every other loop *and* every loop's worker threads before returning, so
  no work callback is running concurrently either. Paused loops and
  workers go RCU-offline, so `synchronize_rcu()` under pause won't hang.
- **Shutdown and destroy are two different phases; only the second one is
  a trap.** At *shutdown* (`shutdown_cb`), teardown jobs are spliced onto
  the async queue and run as ordinary async jobs on a still-live loop —
  they may freely schedule more work, and normally do (that is where you
  drop references). Only when the last loop reference goes away does
  *destroy* (`destroy_cb`) close the handles; `isc__job_close()` and
  `isc__async_close()` then drain the job list and the async queue
  exactly **once** each, and `loop_close()` INSISTs both are empty.
  Anything scheduled from within that final close-phase drain is never
  run and trips the assertion.
- Per-loop state that these callbacks touch is owned by its loop; see
  [[per-loop-affinity]] for the sharding discipline and [[rcu-mutation]]
  for publishing changes readers see concurrently.

## Where to look

`lib/isc/async.c`, `lib/isc/job.c`, `lib/isc/work.c`, wired together in
`lib/isc/loop.c` (`loop_init`, `shutdown_cb`, `destroy_cb`, `pause_loop`).
Design overview in `doc/dev/loopmgr.md`. Behavioural tests, which are the
fastest way to check a claim, are in `tests/isc/{async,job,work,loop}_test.c`.
