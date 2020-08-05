.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.6
---------------------

Security Fixes
~~~~~~~~~~~~~~

- It was possible to trigger an assertion failure by sending a specially
  crafted large TCP DNS message. This was disclosed in CVE-2020-8620.

  ISC would like to thank Emanuel Almeida of Cisco Systems, Inc. for
  bringing this vulnerability to our attention. [GL #1996]

- ``named`` could crash after failing an assertion check in certain
  query resolution scenarios where QNAME minimization and forwarding
  were both enabled. To prevent such crashes, QNAME minimization is now
  always disabled for a given query resolution process, if forwarders
  are used at any point. This was disclosed in CVE-2020-8621.

  ISC would like to thank Joseph Gullo for bringing this vulnerability
  to our attention. [GL #1997]

- It was possible to trigger an assertion failure when verifying the
  response to a TSIG-signed request. This was disclosed in
  CVE-2020-8622.

  ISC would like to thank Dave Feldman, Jeff Warren, and Joel Cunningham
  of Oracle for bringing this vulnerability to our attention. [GL #2028]

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

- A new configuration option ``stale-cache-enable`` has been introduced to
  enable or disable the keeping of stale answers in cache. [GL #1712]

Feature Changes
~~~~~~~~~~~~~~~

- BIND's cache database implementation has been updated to use a faster
  hash-function with better distribution.  In addition, the effective
  max-cache-size (configured explicitly, defaulting to a value based on system
  memory or set to 'unlimited') now pre-allocates fixed size hash tables. This
  prevents interruption to query resolution when the hash tables need to be
  increased in size. [GL #1775]

- The resource records received with 0 TTL are no longer kept in the cache
  to be used for stale answers. [GL #1829]

Bug Fixes
~~~~~~~~~

- Addressed an error in recursive clients stats reporting.
  There were occasions when an incoming query could trigger a prefetch for
  some eligible rrset, and if the prefetch code were executed before recursion,
  no increment in recursive clients stats would take place. Conversely,
  when processing the answers, if the recursion code were executed before the
  prefetch, the same counter would be decremented without a matching increment.
  [GL #1719]

- The introduction of KASP support broke whether the second field
  of sig-validity-interval was treated as days or hours. (Thanks to
  Tony Finch.) [GL !3735]

- The IPv6 Duplicate Address Detection (DAD) mechanism could cause the operating
  system to report the new IPv6 addresses to the applications via the
  getifaddrs() API in a tentative (DAD not yet finished) or duplicate (DAD
  failed) state. Such addresses cannot be bound by an application, and named
  failed to listen on IPv6 addresses after the DAD mechanism finished. It is
  possible to work around the issue by setting the IP_FREEBIND option on the
  socket and trying to bind() to the IPv6 address again if the first bind() call
  fails with EADDRNOTAVAIL. [GL #2038]
