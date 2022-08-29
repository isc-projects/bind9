<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

## Libuv Notes

This document describes various notes related to the using of the libuv library.

### Queueing Events onto the ``uv_loop_t``

The upstream documentation on [the I/O
loop](http://docs.libuv.org/en/v1.x/design.html#the-i-o-loop) describes the
order in which are the various handles processed.  However, it does not describe
the order in which the loop processes the events in the same buckets, and
because it is counterintuitive, it is described here.

When scheduling the events of the same class (f.e. ``uv_*_start()`` or
``uv_close()``), the events are executed in the LIFO order (e.g. it's a stack,
not a queue).  The reasoning for the upstream design choice is described in [the
upstream issue](https://github.com/libuv/libuv/issues/3582).

What does this means in practice?  F.e. when closing the handles:

    uv_close(&handle1, callback1);
	uv_close(&handle2, callback2);

The ``callback2()`` will be called before the ``callback1()``, so if they are
using the same resource, the resource can be freed in the ``callback1()`` and
not in the ``callback2()``.

Same applies f.e. to the ``uv_idle_t``, if you want the ``action1()`` to execute
before ``action2()``, the valid code would be:

    uv_idle_start(&idle2, action2);
    uv_idle_start(&idle1, action1);

which is really counterintuitive.
