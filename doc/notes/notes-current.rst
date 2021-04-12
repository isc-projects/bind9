.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.16
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
  the minimum of the SOA MINIMUM value and the SOA TTL. :gl:`#2347`

- Reduce the supported maximum number of iterations that can be
  configured in an NSEC3 zones to 150. :gl:`#2642`

- Treat DNSSEC responses with NSEC3 iterations greater than 150 as insecure.
  :gl:`#2445`

- Zones that want to transition from secure to insecure mode without making it
  bogus in the process should now first change their ``dnssec-policy`` to
  ``insecure`` (as opposed to ``none``). Only after the DNSSEC records have
  been removed from the zone (in a timely manner), the ``dnssec-policy`` can
  be set to ``none`` (or be removed from the configuration). Setting the
  ``dnssec-policy`` to ``insecure`` will cause CDS and CDNSKEY DELETE records
  to be published. :gl:`#2645`

- Change the ``max-ixfr-ratio`` configuration option default value to
  ``unlimited`` for better backwards compatibility in the stable release
  series. :gl:`#2671`

Bug Fixes
~~~~~~~~~

- When dumping the cache to file, TTLs were being increased with
  ``max-stale-ttl``. Also the comment above stale RRsets could have nonsensical
  values if the RRset was still marked a stale but the ``max-stale-ttl`` has
  passed (and is actually an RRset awaiting cleanup). Both issues have now
  been fixed. :gl:`#389` :gl:`#2289`

- ``named`` would overwrite a zone file unconditionally when it recovered from
  a corrupted journal. :gl:`#2623`

- With ``dnssec-policy``, when creating new keys also check for keyid conflicts
  between the new keys too. :gl:`#2628`

- Update ZONEMD to match RFC 8976. :gl:`#2658`

- With ``dnssec-policy```, don't roll keys if the private key file is offline.
  :gl:`#2596`
