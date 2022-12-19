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

Notes for BIND 9.19.9
---------------------

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

- TLS session resumption might lead to handshake failures when client
  certificates are used for authentication (Mutual TLS).  This has
  been fixed. :gl:`#3725`

- When an outgoing request timed out, the ``named`` would retry up to three
  times with the same server instead of trying a next available name server.
  This has been fixed. :gl:`#3637`

- Recently used ADB names and ADB entries (IP addresses) could get cleaned when
  ADB would be under memory pressure.  To mitigate this, count only actual ADB
  names and ADB entries into the overmem memory limit (exclude internal memory
  structures used for "housekeeping") and exclude recently used (<= 10 seconds)
  ADB names and entries from the overmem memory cleaner. :gl:`#3739`

- Fix a rare assertion failure in the outgoing TCP DNS connection handling.
  :gl:`#3178` :gl:`#3636`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
