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

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- BIND's cache database implementation has been updated to use a faster
  hash-function with better distribution.  In addition, the effective
  max-cache-size (configured explicitly, defaulting to a value based on system
  memory or set to 'unlimited') now pre-allocates fixed size hash tables. This
  prevents interruption to query resolution when the hash tables need to be
  increased in size. [GL #1775]

Bug Fixes
~~~~~~~~~

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
