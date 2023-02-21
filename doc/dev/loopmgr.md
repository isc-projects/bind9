<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

# Loop Manager

This document aims to describe the design of the basic event loop handling in
the BIND 9.

Every application is expected to create and use a single ``isc_loopmgr_t``
instance, but the ``isc_loopmgr`` API itself doesn't enforce this requirement.

## Event Loops

The loop manager creates *N* event loops (of type ``isc_loop_t``), where *N* is
specified by the caller when creating the loop manager.  The number of event
loops is usually same as the number of logical CPUs.  The minimum *N* is 1, and
maximum is limited only by the machine resources.

For each event loop, a thread is created by the loop manager.  The
``isc_loop_t`` object itself is built on top of ``uv_loop_t``.  ``uv_loop_t``
is not thread-safe, and this is also true for ``isc_loop_t``.  If you need to
run an event on a different event loop, see below for the ``isc_async`` API.

The application can get a reference to the current event loop using
``isc_loop_current()``, to the main event loop (loop 0) that will always exist
using ``isc_loop_main()`` and to an arbitrary event loop using
``isc_loop_get()``.

## Application Start and Stop

Every application MUST add its initial events using ``isc_loopmgr_setup()`` to
be run on all initialized event loops or ``isc_loop_setup()`` to be run on a
selected event loop.

Applications MAY also add events to be run when the application is shut down by
calling ``isc_loopmgr_teardown()`` (or ``isc_loop_teardown()`` for a specific
event loop).

After the setup and teardown events have been configured, the application may
be started via ``isc_loopmgr_run()``.  ``isc_loopmgr_run()`` will block for the
caller while event loops are running.  When the work is done,
``isc_loopmgr_shutdown()`` must be run from within one of the event loops; this
will cause all loops to be shut down and ``isc_loopmgr_run()`` to return.

The most notable change from the ``isc_app`` API is the lack of a blocked
``main`` thread.  The loop manager starts the **main** event loop on the
**main** thread when the application is started.

This API now replaces the old ``isc_app`` API.

## Signal Handling

The loop manager itself takes care of handling the ``SIGTERM`` and ``SIGINT``
signals, but the application MAY add more handlers via ``isc_signal`` API.  In
``named``, for example, ``SIGHUP`` is used to trigger an application reload.

## Event scheduling

The application may add events to the event loop via ``isc_job_run()`` for jobs
on the same event loop, or via ``isc_async_run()`` for jobs to be passed to
other event loops.  Both functions take the event loop, the callback and the
callback argument as parameters.

Generally ``isc_job_run()`` is more direct, as it schedules the event directly
on the event loop and doesn't use locking, and should be preferred unless you
need to run the event on a different thread.

``isc_async_run()`` is the only new thread-safe function provided by the loop
manager, uses locked list to collect new jobs and uv_async() primitive to
enqueue the collected jobs onto the event loop.

## Timers

The ``isc_timer`` API is built on top of the ``uv_timer_t`` object.
It supports ``ticker`` and ``once`` timers, and uses ``isc_timer_start()``
and ``isc_timer_stop()`` to start and stop timers. The ``isc_timer_t``
object is not thread-safe.

## Network Manager

The network manager is built on top loop manager event loops rather than
managing its own event loops.  Network manager calls are not thread-safe:
all connect/read/write functions MUST be called from the thread that created
the network manager socket.

The ``isc_nm_listen*()`` functions MUST be called from the ``main`` loop.

The general design of Network Manager is based on callbacks.  Callback
functions should always be called asynchronously by the network manager,
because the caller might be holding a lock, and the callback may try to
acquire the same lock.  So even if a network manager function is able to
determine a result immediately, the callback must be scheduled onto the
event loop instead of executed directly.
