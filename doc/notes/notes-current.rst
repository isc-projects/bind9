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

- The ``named`` daemon uses load-balanced sockets to increase performance by
  distributing the incoming queries among multiple threads.  Currently, the only
  operating systems that support load-balanced sockets are Linux and FreeBSD 12,
  thus both UDP and TCP performance is limited to a single-thread on systems
  without load-balancing socket support. [GL #2137]

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

- Adjust the ``max-recursion-queries`` default from 75 to 100. Since the
  queries sent towards root and TLD servers are now included in the
  count (as a result of the fix for CVE-2020-8616), ``max-recursion-queries``
  has a higher chance of being exceeded by non-attack queries, which is the
  main reason for increasing its default value. [GL #2305]

- Restore the ``nocookie-udp-size`` default from 1232 to 4096. Normally the
  EDNS buffer size is configured by ``max-udp-size``, but this configuration
  option overrides the value, but most people don't and won't realize there's
  an extra configuration option that needs to be tweaked. By changing the
  default here, we allow the the ``max-udp-size`` to be the sole option that
  needs to be changed when operator wants to change the default EDNS buffer
  size. [GL #2250]

Bug Fixes
~~~~~~~~~

- The synthesised CNAME from a DNAME was incorrectly followed when the QTYPE
  was CNAME or ANY. [GL #2280]

- Tighten handling of missing DNS COOKIE responses over UDP by
  falling back to TCP. [GL #2275]

- Building with native PKCS#11 support for AEP Keyper has been broken
  since BIND 9.17.4. This has been fixed. [GL #2315]
