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

Notes for BIND 9.18.15
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

- None.

Bug Fixes
~~~~~~~~~

- When ISC_R_INVALIDPROTO (ENOPROTOOPT, EPROTONOSUPPORT) is returned from
  libuv, treat it as a network failure, mark the server as broken and don't
  try again. :gl:`#4005`

- The :any:`max-transfer-time-in` and :any:`max-transfer-idle-in` options
  were not implemented when the BIND 9 networking stack was refactored
  in 9.16. The missing functionality has been re-implemented and
  incoming zone transfers now time out properly when not progressing.
  :gl:`#4004`

- Log file rotation did not clean up older versions of log files when the
  logging :any:`channel` configured an absolute path as ``file`` destination.
  This has now been fixed. :gl:`#3991`.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
