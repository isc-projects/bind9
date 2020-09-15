.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.7
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- New ``rndc`` command ``rndc dnssec -checkds`` to tell ``named``
  that a DS record for a given zone or key has been published or withdrawn
  from the parent. Replaces the time-based ``parent-registration-delay``
  configuration option. [GL #1613]

- Log when ``named`` adds a CDS/CDNSKEY to the zone. [GL #1748]

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- In rare circumstances, named would exit with assertion failure when the number
  of nodes stored in the red-black-tree exceeds the maximum allowed size of the
  internal hashtable.  [GL #2104]

- Silence spurious system log messages for EPROTO(71) error code that has been
  seen on older operating systems where unhandled ICMPv6 errors result in a
  generic protocol error being returned instead of the more specific error code.
  [GL #1928]

- With query minimization enabled, named failed to resolve ip6.arpa. names
  that had more labels before the IPv6 part. For example, when named
  implemented query minimization on a name like
  ``A.B.1.2.3.4.(...).ip6.arpa.``, it stopped at the left-most IPv6 label, i.e.
  ``1.2.3.4.(...).ip6.arpa.`` without considering the extra labels ``A.B``.
  That caused a query loop when resolving the name: if named received
  NXDOMAIN answers, then the same query was repeatedly sent until the number
  of queries sent reached the value in the ``max-recursion-queries``
  configuration option. [GL #1847]
