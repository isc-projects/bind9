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

- NSEC3 support was added to KASP. A new option for ``dnssec-policy``,
  ``nsec3param``, can be used to set the desired NSEC3 parameters.
  NSEC3 salt collisions are automatically prevented during resalting.
  [GL #1620]

- ``dig`` output now includes the transport protocol used (UDP, TCP, or
  TLS). [GL #1816]

- ``dig`` can now report the DNS64 prefixes in use (``+dns64prefix``).
  This is useful when the host on which ``dig`` is run is behind an
  IPv6-only link, using DNS64/NAT64 or 464XLAT for IPv4aaS (IPv4 as a
  Service). [GL #1154]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Earlier releases of BIND versions 9.16 and newer required the
  operating system to support load-balanced sockets in order for
  ``named`` to be able to achieve high performance (by distributing
  incoming queries among multiple threads). However, the only operating
  systems currently known to support load-balanced sockets are Linux and
  FreeBSD 12, which means both UDP and TCP performance were limited to a
  single thread on other systems. As of BIND 9.17.8, ``named`` attempts
  to distribute incoming queries among multiple threads on systems which
  lack support for load-balanced sockets (except Windows). [GL #2137]

- The default value of ``max-recursion-queries`` was increased from 75
  to 100. Since the queries sent towards root and TLD servers are now
  included in the count (as a result of the fix for CVE-2020-8616),
  ``max-recursion-queries`` has a higher chance of being exceeded by
  non-attack queries, which is the main reason for increasing its
  default value. [GL #2305]

- The default value of ``nocookie-udp-size`` was restored back to 4096
  bytes. Since ``max-udp-size`` is the upper bound for
  ``nocookie-udp-size``, this change relieves the operator from having
  to change ``nocookie-udp-size`` together with ``max-udp-size`` in
  order to increase the default EDNS buffer size limit.
  ``nocookie-udp-size`` can still be set to a value lower than
  ``max-udp-size``, if desired. [GL #2250]

- ``ipv4only.arpa`` is now served when ``dns64`` is configured. [GL #385]

- When using the ``unixtime`` or ``date`` method to update the SOA
  serial number, ``named`` and ``dnssec-signzone`` silently fell back to
  the ``increment`` method to prevent the new serial number from being
  smaller than the old serial number (using serial number arithmetics).
  ``dnsssec-signzone`` now prints a warning message, and ``named`` logs
  a warning, when such a fallback happens. [GL #2058]

Bug Fixes
~~~~~~~~~

- Handling of missing DNS COOKIE responses over UDP was tightened by
  falling back to TCP. [GL #2275]

- The CNAME synthesized from a DNAME was incorrectly followed when the
  QTYPE was CNAME or ANY. [GL #2280]

- Building with native PKCS#11 support for AEP Keyper has been broken
  since BIND 9.17.4. This has been fixed. [GL #2315]
