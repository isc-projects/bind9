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

Notes for BIND 9.19.13
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

- When the same ``notify-source`` address and port number was configured for
  multiple destinations and zones, an unresponsive server could tie up the
  socket until it timed out; in the meantime, NOTIFY messages for other servers
  silently failed.``named`` will now retry these failing messages over TCP.
  NOTIFY failures are now logged at level INFO. :gl:`#4001` :gl:`#4002`

- When ISC_R_INVALIDPROTO (ENOPROTOOPT, EPROTONOSUPPORT) is returned from
  libuv, treat it as a network failure, mark the server as broken and don't
  try again. :gl:`#4005`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
