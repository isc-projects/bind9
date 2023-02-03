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

Notes for BIND 9.16.38
----------------------

Bug Fixes
~~~~~~~~~

- A constant stream of zone additions and deletions via ``rndc reconfig`` could
  cause increased memory consumption due to delayed cleaning of view memory.
  This has been fixed. :gl:`#3801`

- Improve the speed of the message digest algorithms (MD5, SHA-1,
  SHA-2) and NSEC3 hashing. :gl:`#3795`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
