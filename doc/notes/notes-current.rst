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

Notes for BIND 9.19.12
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- BIND now depends on ``liburcu``, Userspace RCU, for lock-free data
  structures. :gl:`#3934`

Removed Features
~~~~~~~~~~~~~~~~

- The TKEY Mode 2 (Diffie-Hellman Exchanged Keying Mode) has been removed and
  using TKEY Mode 2 is now a fatal error.  Users are advised to switch to TKEY
  Mode 3 (GSS-API). :gl:`#3905`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
