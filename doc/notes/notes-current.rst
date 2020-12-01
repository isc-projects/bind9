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
  NSEC3 parameters, and will detect collisions when resalting. [GL #1620].

- Adjust the ``max-recursion-queries`` default from 75 to 100. Since the
  queries sent towards root and TLD servers are now included in the
  count (as a result of the fix for CVE-2020-8616), ``max-recursion-queries``
  has a higher chance of being exceeded by non-attack queries, which is the
  main reason for increasing its default value. [GL #2305]

Bug Fixes
~~~~~~~~~

- The synthesised CNAME from a DNAME was incorrectly followed when the QTYPE
  was CNAME or ANY. [GL #2280]

- Tighten handling of missing DNS COOKIE responses over UDP by
  falling back to TCP. [GL #2275]

- Building with native PKCS#11 support for AEP Keyper has been broken
  since BIND 9.16.6. This has been fixed. [GL #2315]
