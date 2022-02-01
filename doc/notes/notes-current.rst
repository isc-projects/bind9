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

Notes for BIND 9.17.23
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- The IPv6 sockets are now explicitly restricted to sending and receiving IPv6
  packets only.  This renders the ``dig`` option ``+mapped`` non-functioning and
  thus the option has been removed. :gl:`#3093`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- With libuv >= 1.37.0, the recvmmsg support would not be enabled in ``named``
  reducing the maximum query-response performance.  The recvmmsg support would
  be used only in libuv 1.35.0 and 1.36.0.  This has been fixed.  :gl:`#3095`

- A failed view configuration during a named reconfiguration procedure could
  cause inconsistencies in BIND internal structures, causing a crash or other
  unexpected errors.  This has been fixed.  :gl:`#3060`

- Restore logging "quota reached" message when accepting connection is over
  hard quota.  :gl:`#3125`
