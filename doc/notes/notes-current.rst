.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. _relnotes-9.16.4:

Notes for BIND 9.16.4
=====================

.. _relnotes-9.16.4-security:

Security Fixes
--------------

-  None.

.. _relnotes-9.16.4-known:

Known Issues
------------

-  None

.. _relnotes-9.16.4-changes:

Feature Changes
---------------

-  ``dig`` and other tools can now print the Extended DNS Error (EDE)
   option when it appears in a request or response. [GL #1834]

.. _relnotes-9.16.4-bugs:

Bug Fixes
---------

- ``named`` could crash with an assertion failure if the name of a database node
    was looked up while the database was being modified. [GL #1857]
- Missing mutex and conditional destruction in netmgr code leads to a memory
  leak on BSD systems. [GL #1893].
