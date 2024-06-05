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

Notes for BIND 9.19.25
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Added a new statistics variable ``recursive high-water`` that reports
  the maximum number of simultaneous recursive clients BIND has handled
  while running. :gl:`#4668`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Outgoing zone transfers are no longer enabled by default. An explicit
  :any:`allow-transfer` ACL must now be set at the :any:`zone`, :any:`view` or
  :namedconf:ref:`options` level to enable outgoing transfers. :gl:`#4728`

Bug Fixes
~~~~~~~~~

- An RPZ response's SOA record TTL was set to 1 instead of the SOA TTL, if
  ``add-soa`` was used. This has been fixed. :gl:`#3323`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
