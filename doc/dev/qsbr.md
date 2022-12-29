<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

QSBR: quiescent state based reclamation
=======================================

QSBR is a safe memory reclamation (SMR) algorithm for lock-free data
structures such as a qp-trie. (See `doc/dev/qp.md`.)

When an object is unlinked from a lock-free data structure, it
cannot be `free()`ed immediately, because there can still be readers
accessing the object via an old version of the data structure. SMR
algorithms determine when it is safe to reclaim memory after it has
been unlinked.


Introductions and overviews
---------------------------

There is a terse overview in `include/isc/qsbr.h`.

Jeff Preshing has a nice introduction to QSBR,
_<https://preshing.com/20160726/using-quiescent-states-to-reclaim-memory/>_

At the end of this note is a copy of a blog post about writing BIND's
`isc_qsbr`, _<https://dotat.at/@/2023-01-10-qsbr.html>_

[Paul McKenney's web page][paulmck] has links to his book on
concurrent programming, the [Userspace RCU library][urcu], and more.
McKenney invented RCU and QSBR. RCU is the Linux kernel's machinery
for lock-free data structures and safe memory reclamation, based on
QSBR.

[paulmck]: http://www.rdrop.com/~paulmck/
[urcu]: https://liburcu.org/


Example code
------------

If you are implementing a lock-free data structure that needs safe
memory reclamation, here's a guide to using `isc_qsbr`, based on how
QSBR is used by `dns_qp`.

### registration

When the program starts up you need to register a global callback
function that will reclaim unused memory. You can do so using an
ISC_CONSTRUCTOR function that runs automatically at startup.

        static void
        qp_qsbr_register(void) ISC_CONSTRUCTOR;
        static void
        qp_qsbr_register(void) {
            isc_qsbr_register(qp_qsbr_reclaimer);
        }

### work list

Your module will need somewhere that your callback can find the work
it needs to do. The qp-trie has an atomic list of `dns_qpmulti_t`
objects for this purpose.

        /* a global variable */
        static ISC_ASTACK(dns_qpmulti_t) qsbr_work;

The reason for using global variables is so that we don't need to
allocate a thunk every time we have memory reclamation work to do.

### read-only access

You should design your data structure so that it has a single atomic
root pointer referring to its current version. A lock-free reader
_must_ run in an `isc_loop` callback. It gains access to the data
structure by taking a copy of this pointer:

        qp_node_t *reader = atomic_load_acquire(&multi->reader);

During an `isc_loop` callback, a reader should keep using the same
pointer go get a consistent view of the data structure. If it reloads
the pointer it can get a different version changed by concurrent
writers.

A reader _must_ stop using the root pointer and any interior pointers
obtained via the root pointer before it returns to the `isc_loop`.

### modifications and writes

All changes to the data structure must be copy-on-write (aka
read-copy-update) so that concurrent readers are not disturbed.

When a new version of the data structure has been prepared, it is
committed by overwriting the atomic root pointer,

        atomic_store_release(&multi->reader, reader); /* COMMIT */

### scheduling cleanup

After committing a change, your data structure may have memory that
will become free, after concurrent readers have stopped accessing it.
To reclaim the memory when it is safe, use code like:

        isc_qsbr_phase_t phase = isc_qsbr_phase(multi->loopmgr);
        if (defer_chunk_reclamation(qp, phase)) {
            ISC_ASTACK_ADD(qsbr_work, multi, cleanup);
            isc_qsbr_activate(multi->loopmgr, phase);
        }

  * First, get the current QSBR phase

  * Second, mark free memory with the phase number. The qp-trie scans
    its chunks and marks those that will become free, and returns
    `true` if there is cleanup work to do.

  * If so, the qp-trie is added to the work list. (`ISC_ALIST_ADD()`
    is idempotent).

  * Finally, QSBR is informed that there is work to do.

In other cases it might not make sense to scan the data structure
after committing, and instead you might make note of which memory to
clean up while making changes before you know what the phase will be.
You can then have per-phase work lists, like:

        static ISC_ASTACK(my_work_t) qsbr_work[ISC_QSBR_PHASES];

        isc_qsbr_phase_t phase = isc_qsbr_phase(loopmgr);
        ISC_ASTACK_ADD(qsbr_work[phase], cleanup_work, link);
        isc_qsbr_activate(loopmgr, phase);

In general, there will be several (maybe many) write operations during
a grace period. Your lock-free data structure should collect its
reclamation work from all these writes into a batch per phase, i.e.
per grace period.

### reclaiming

Inside the reclaimer callback, we iterate over the work list and clean
up each item on it. If there is more cleanup work to do in another
phase, we put the qp-trie back on the work list for another go.

        static void
        qsbreclaimer(void *arg, isc_qsbr_phase_t phase) {
            UNUSED(arg);

            ISC_STACK(dns_qpmulti_t) drain = ISC_ASTACK_TO_STACK(qsbr_work);
            while (!ISC_STACK_EMPTY(drain)) {
                dns_qpmulti_t *multi = ISC_STACK_POP(drain, cleanup);
                INSIST(QPMULTI_VALID(multi));
                LOCK(&multi->mutex);
                if (reclaim_chunks(&multi->writer, phase)) {
                    /* more to do next time */
                    ISC_ALIST_PUSH(qsbr_work, multi, cleanup);
                }
                UNLOCK(&multi->mutex);
            }
        }

### reclaim marks

In the qp-trie data structure, each chunk has some metadata which
includes a bitfield for the reclaim phase:

        isc_qsbr_phase_t phase : ISC_QSBR_PHASE_BITS;

We use a bitfield so that all the metadata fits in a single word.


------------------------------------------------------------------------

Safe memory reclamation for BIND
================================

At the end of October 2022, I _finally_ got [my multithreaded
qp-trie][qp-gc] working! It could be built with two different
concurrency control mechanisms:

  * A reader/writer lock

    This has poor read-side scalability, because every thread is
    hammering on the same shared location. But its write performance
    is reasonably good: concurrent readers don't slow it down too much.

  * [`liburcu`, userland read-copy-update][urcu]

    RCU has a fast and scalable read side, nice! But on the write side
    I used `synchronize_rcu()`, which is blocking and rather slow, so
    my write performance was terrible.

OK, but I want the best of both worlds! To fix it, I needed to change
the qp-trie code to use safe memory reclamation more effectively:
instead of blocking inside `synchronize_rcu()` before cleaning up, use
`call_rcu()` to clean up asynchronously. I expect I'll write about the
qp-trie changes another time.

Another issue is that I want the best of both worlds _by default_,
but `liburcu` is [LGPL][] and we don't want BIND to depend on
code whose licence demands more from our users than the [MPL][].

[qp-gc]: https://dotat.at/@/2021-06-23-page-based-gc-for-qp-trie-rcu.html
[LGPL]: https://opensource.org/licenses/LGPL-2.1
[MPL]: https://opensource.org/licenses/MPL-2.0

So I set out to write my own safe memory reclamation support code.


lock freedom
------------

In a [multithreaded qp-trie][qp-gc], there can be many concurrent
readers, but there can be only one writer at a time and modifications
are strictly serialized. When I have got it working properly, readers
are completely wait-free, unaffected by other readers, and almost
unaffected by writers. Writers need to get a mutex to ensure there is
only one at a time, but once the mutex is acquired, a writer is not
obstructed by readers.

The way this works is that readers use an atomic load to get a pointer
to the root of the current version of the trie. Readers can make
multiple queries using this root pointer and the results will be
consistent wrt that particular version, regardless of what changes
writers might be making concurrently. Writers do not affect readers
because all changes are made by copy-on-write. When a writer is ready
to commit a new version of the trie, it uses an atomic store to flip
the root pointer.


safe memory reclamation
-----------------------

We can't copy-on-write indefinitely: we need to reclaim the memory
used by old versions of the trie. And we must do so "safely", i.e.
without `free()`ing memory that readers are still using.

So, before `free()`ing memory, a writer must wait for a _"grace
period"_, which is a jargon term meaning "until readers are not using
the old version". There are a bunch of algorithms for determining when
a grace period is over, with varying amounts of over-approximation,
CPU overhead, and memory backlog.

The [RCU][urcu] function `synchronize_rcu()` is slow because it blocks
waiting for a grace period; the `call_rcu()` function runs a callback
asynchronously after a grace period has passed. I wanted to avoid
blocking my writers, so I needed to implement something like
`call_rcu()`.


aversions
---------

When I started trying to work out how to do safe memory reclamation,
it all seemed quite intimidating. But as I learned more, I found that
my circumstances make it easier than it appeared at first.

The [`liburcu`][urcu] homepage has a long list of supported CPU
architectures and operating systems. Do I have to care about those
details too? No! The RCU code dates back to before the age of
standardized concurrent memory models, so the RCU developers had to
invent their own atomic primitives and correctness rules. Twenty-ish
years later the state of the art has advanced, so I can use
`<stdatomic.h>` without having to re-do it like `liburcu`.

You can also choose between several algorithms implemented by
[`liburcu`][urcu], involving questions about kernel support, specially
reserved signals, and intrusiveness in application code. But while I
was working out how to schedule asynchronous memory reclamation work,
I realised that BIND is already well-suited to the fastest flavour of
RCU, called "QSBR".


QSBR
----

QSBR stands for "quiescent state based reclamation". A _"quiescent
state"_ is a fancy name for a point when a thread is not accessing a
lock-free data structure, and does not retain any root pointers or
interior pointers.

When a thread has passed through a quiescent state, it no longer has
access to older versions of the data structures. When _all_ threads
have passed through quiescent states, then nothing in the program has
access to old versions. This is how QSBR detects grace periods: after
a writer commits a new version, it waits for all threads to pass
through quiescent states, and therefore a grace period has definitely
elapsed, and so it is then safe to reclaim the old version's memory.

QSBR is fast because readers do not need to explicitly mark the
critical section surrounding the atomic load that I mentioned earlier.
Threads just need to pass through a quiescent state frequently enough
that there isn't a huge build-up of unreclaimed memory.

Inside an operating system kernel (RCU's native environment), a
context switch provides a natural quiescent state. In a userland
application, you need to find a good place to call
`rcu_quiescent_state()`. You could call it every time you have
finished using a root pointer, but marking a quiescent state is not
completely free, so there are probably more efficient ways.


`libuv`
-------

BIND is multithreaded, and (basically) each thread runs an event loop.
Recent versions of BIND use [`libuv`][uv] for the event loops.

A lot of things started falling into place when I realised that the
`libuv` event loop gives BIND a [natural quiescent state][uv-loop]:
when the event callbacks have finished running, and `libuv` is about
to call `select()` or `poll()` or whatever, we can mark a quiescent
state. We can require that event-handling functions do not stash root
pointers in the heap, but only use them via local variables, so we
know that old versions are inaccessible after the callback returns.

My design marks a quiescent state once per loop, so on a busy server
where each loop has lots to do, the cost of marking a quiescent state
is amortized across several I/O events.

[uv]: http://libuv.org/
[uv-loop]: http://docs.libuv.org/en/v1.x/design.html#the-i-o-loop


fuzzy barrier
-------------

So, how do we mark a quiescent state? Using a _"fuzzy barrier"_.

When a thread reaches a normal barrier, it blocks until all the other
threads have reached the barrier, after which exactly one of the
threads can enter a protected section of code, and the others are
unblocked and can proceed as normal.

When a thread encounters a fuzzy barrier, it never blocks. It either
proceeds immediately as normal, or if it is the last thread to reach
the barrier, it enters the protected code.

RCU does not actually use a fuzzy barrier as I have described it. Like
a fuzzy barrier, each thread keeps track of whether it has passed
through a quiescent state in the current grace period, without
blocking; but unlike a fuzzy barrier, no thread is diverted to the
protected code. Instead, code that wants to enter a protected section
uses the blocking `synchronize_rcu()` function.


EBR-ish
-------

As in the paper ["performance of memory reclamation for lockless
synchronization"][HMBW], my implementation of QSBR uses a fuzzy
barrier designed for another safe memory reclamation algorithm, EBR,
epoch based reclamation. (EBR was invented here in Cambridge by [Keir
Fraser][tr579].)

[HMBW]: http://csng.cs.toronto.edu/publication_files/0000/0159/jpdc07.pdf
[tr579]: https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-579.html

Actually, my fuzzy barrier is slightly different to EBR's. In EBR, the
fuzzy barrier is used every time the program enters a critical
section. (In qp-trie terms, that would be every time a reader fetches
a root pointer.) So it is vital that EBR's barrier avoids mutating
shared state, because that would wreck multithreaded performance.

Because BIND will only pass through the fuzzy barrier when it is about
to use a blocking system call, my version mutates shared state more
frequently (typically, once per CPU per grace period, instead of once
per grace period). If this turns out to be a problem, it won't be too
hard to make it work more like EBR.

More trivially, I'm using the term "phase" instead of "epoch", because
it's nothing to do with the unix epoch, because there are three
phases, and because I can talk about phase transitions and threads
being out of phase with each other.


coda
----

While reading various RCU-related papers, I was amused by ["user-level
implementations of read-copy update"][DMSDW], which says:

> BIND, a major domain-name server used for Internet domain-name
> resolution, is facing scalability issues. Since domain names
> are read often but rarely updated, using user-level RCU might be
> beneficial.

Yes, I think it might :-)

[DMSDW]: https://www.efficios.com/publications/
