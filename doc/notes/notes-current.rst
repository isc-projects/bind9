.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. _relnotes-9.16.5:

Notes for BIND 9.16.5
=====================

.. _relnotes-9.16.5-security:

Security Fixes
--------------

- None.

.. _relnotes-9.16.5-known:

-  It was possible to trigger an assertion when attempting to fill an
   oversized TCP buffer. This was disclosed in CVE-2020-8618. [GL #1850]

-  It was possible to trigger an INSIST failure when a zone with an
   interior wildcard label was queried in a certain pattern. This was
   disclosed in CVE-2020-8619. [GL #1111] [GL #1718]

Known Issues
------------

- None

.. _relnotes-9.16.5-changes:

Feature Changes
---------------

- None.

.. _relnotes-9.16.5-bugs:

Bug Fixes
---------

- Properly handle missing ``kyua`` command so that ``make check`` does
  not fail unexpectedly when CMocka is installed, but Kyua is not.
  [GL #1950]
