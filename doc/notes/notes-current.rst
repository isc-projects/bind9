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

Notes for BIND 9.19.14
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- A new option to :any:`dnssec-policy` has been added, :any:`cdnskey`, that
  allows you to enable or disable the publication of CDNSKEY records.
  :gl:`#4050`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Improve the responsiveness of the ``named`` serving as an authoritative DNS
  server for a delegation-heavy zone(s) shortly after loading such zone(s).
  :gl:`#4045`

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
