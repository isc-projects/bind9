.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.6
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- A new configuration option, ``stale-refresh-time``, has been
  introduced. It allows a stale RRset to be served directly from cache
  for a period of time after a failed lookup, before a new attempt to
  refresh it is made. [GL #2066]

- ``dig`` can now report the DNS64 prefixes in use (``+dns64prefix``).
  This is useful when the host on which ``dig`` is run is behind an
  IPv6-only link, using DNS64/NAT64 or 464XLAT for IPv4aaS (IPv4 as a
  Service). [GL #1154]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The network manager API is now used by ``named`` to send zone transfer
  requests. [GL #2016]

- The ``dig``, ``host``, and ``nslookup`` tools have been converted to
  use the new network manager API rather than the older ISC socket API.

  As a side effect of this change, the ``dig +unexpected`` option no
  longer works. This could previously be used to diagnose broken servers
  or network configurations by listening for replies from servers other
  than the one that was queried. With the new API, such answers are
  filtered before they ever reach ``dig``, so the option has been
  removed. [GL #2140]

- Support for DNS over TLS (DoT) has been added: the ``dig`` tool is now
  able to send DoT queries (``+tls`` option) and ``named`` can handle
  DoT queries (``listen-on tls ...`` option). ``named`` can use either a
  certificate provided by the user or an ephemeral certificate generated
  automatically upon startup. [GL #1840]

- Add NSEC3 support for zones that manage their DNSSEC with the `dnssec-policy`
  configuration. A new option 'nsec3param' can be used to set the desired
  NSEC3 parameters, and will detect collisions when resalting. [GL #1620].

Bug Fixes
~~~~~~~~~

- ``UV_EOF`` is no longer treated as a ``TCP4RecvErr`` or a
  ``TCP6RecvErr``. [GL #2208]

- ``named`` could crash with an assertion failure if a TCP connection
  were closed while a request was still being processed. [GL #2227]

- The synthesised CNAME from a DNAME was incorrectly followed when the QTYPE
  was CNAME or ANY. [GL #2280]
