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

Notes for BIND 9.16.25
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

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The default memory allocator has been switched from ``internal`` to
  ``external`` and new command line option ``-M internal`` has been added to
  ``named``. :gl:`#2398`

Bug Fixes
~~~~~~~~~

- If signatures created by the ZSK are expired, and the ZSK private key is offline,
  allow the expired signatures to be replaced with signatures created by the KSK.
  :gl:`#3049`

- On FreeBSD, a TCP connection would leak a small amount of heap memory leading
  to out-of-memory problem in a long run. This has been fixed. :gl:`#3051`

- Overall memory use by ``named`` was optimized and reduced.  :gl:`#2398`

- Under certain circumstances, the signed version of an inline-signed
  zone could be dumped to disk without the serial number of the unsigned
  version of the zone, preventing resynchronization of zone contents
  after ``named`` restart in case the unsigned zone file gets modified
  while ``named`` is not running. This has been fixed. :gl:`#3071`

- With libuv >= 1.37.0, the recvmmsg support would not be enabled in ``named``
  reducing the maximum query-response performance.  The recvmmsg support would
  be used only in libuv 1.35.0 and 1.36.0.  This has been fixed.  :gl:`#3095`
