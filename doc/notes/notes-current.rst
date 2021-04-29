.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.13
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

- Implement ``draft-vandijk-dnsop-nsec-ttl``, NSEC(3) TTL values are now set to
  the minimum of the SOA MINIMUM value and the SOA TTL. [GL #2347].

- Reduce the supported maximum number of iterations that can be
  configured in an NSEC3 zones to 150. [GL #2642]

Bug Fixes
~~~~~~~~~

- When dumping the cache to file, TTLs were being increased with
  ``max-stale-ttl``. Also the comment above stale RRsets could have nonsensical
  values if the RRset was still marked a stale but the ``max-stale-ttl`` has
  passed (and is actually an RRset awaiting cleanup). Both issues have now
  been fixed. [GL #389] [GL #2289]

- ``named`` would overwrite a zone file unconditionally when it recovered from
  a corrupted journal. [GL #2623]

- After the networking manager was introduced to ``named`` to handle
  incoming traffic, it was discovered that the recursive performance had been
  degraded compared to the previous version (9.11).  This has been now fixed by
  running internal tasks inside the networking manager worker threads, so
  they do not compete for resources. [GL #2638]

- With ``dnssec-policy``, when creating new keys also check for keyid conflicts
  between the new keys too. [GL #2628]
