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

Bug Fixes
~~~~~~~~~

- The :any:`max-transfer-time-in` and :any:`max-transfer-idle-in`
  statements have not had any effect since the BIND 9 networking stack
  was refactored in version 9.16. The missing functionality has been
  re-implemented and incoming zone transfers now time out properly when
  not progressing. :gl:`#4004`

- The read timeout in :iscman:`rndc` is now 60 seconds, matching the
  behavior in BIND 9.16 and earlier. It had previously been lowered to
  30 seconds by mistake. :gl:`#4046`

- When the ``ISC_R_INVALIDPROTO`` (``ENOPROTOOPT``, ``EPROTONOSUPPORT``)
  error code is returned by libuv, it is now treated as a network
  failure: the server for which that error code is returned gets marked
  as broken and is not contacted again during a given resolution
  process. :gl:`#4005`

- Log file rotation code did not clean up older versions of log files
  when the logging :any:`channel` had an absolute path configured as a
  ``file`` destination. This has been fixed. :gl:`#3991`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
