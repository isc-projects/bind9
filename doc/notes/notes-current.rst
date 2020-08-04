.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.4
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- ``rndc`` has been updated to use the new BIND network manager API.
  This change had the side effect of altering the TCP timeout for RNDC
  connections from 60 seconds to the ``tcp-idle-timeout`` value, which
  defaults to 30 seconds. Also, because the network manager currently
  has no support for UNIX-domain sockets, those cannot now be used
  with ``rndc``. This will be addressed in a future release, either by
  restoring UNIX-domain socket support or by formally declaring them
  to be obsolete in the control channel. [GL #1759]

- Statistics channels have also been updated to use the new BIND network
  manager API. [GL #2022]

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

- Keeping stale answers in cache has been disabled by default.

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
