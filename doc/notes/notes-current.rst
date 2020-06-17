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
