.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.8
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- ``dig`` can now report the DNS64 prefixes in use (``+dns64prefix``).
  This is useful when the host on which ``dig`` is run is behind an
  IPv6-only link, using DNS64/NAT64 or 464XLAT for IPv4aaS (IPv4 as a
  Service). [GL #1154]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Add NSEC3 support for zones that manage their DNSSEC with the `dnssec-policy`
  configuration. A new option 'nsec3param' can be used to set the desired
  NSEC3 parameters, and will detect collisions when resalting. [GL #1620].

Bug Fixes
~~~~~~~~~

- The synthesised CNAME from a DNAME was incorrectly followed when the QTYPE
  was CNAME or ANY. [GL #2280]

- Tighten handling of missing DNS COOKIE responses over UDP by
  falling back to TCP. [GL #2275]
