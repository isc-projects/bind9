.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Notes for BIND 9.16.39
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- libuv support for receiving multiple UDP messages in a single system
  call (``recvmmsg()``) has been tweaked several times between libuv
  versions 1.35.0 and 1.40.0; the recommended libuv version is 1.40.0 or
  higher. New rules are now in effect for running with a different
  version of libuv than the one used at compilation time. These rules
  may trigger a fatal error at startup:

  - Building against or running with libuv versions 1.35.0 and 1.36.0 is
    now a fatal error.

  - Running with libuv version higher than 1.34.2 is now a fatal error
    when :iscman:`named` is built against libuv version 1.34.2 or lower.

  - Running with libuv version higher than 1.39.0 is now a fatal error
    when :iscman:`named` is built against libuv version 1.37.0, 1.38.0,
    1.38.1, or 1.39.0.

  This prevents the use of libuv versions that may trigger an assertion
  failure when receiving multiple UDP messages in a single system call.
  :gl:`#3840`

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.
