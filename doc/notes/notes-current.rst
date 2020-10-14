.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.10
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

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

- Add NSEC3 support for zones that manage their DNSSEC with the `dnssec-policy`
  configuration. A new option 'nsec3param' can be used to set the desired
  NSEC3 parameters. [GL #1620].

Bug Fixes
~~~~~~~~~

- The synthesised CNAME from a DNAME was incorrectly followed when the QTYPE
  was CNAME or ANY. [GL #2280]
