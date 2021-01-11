.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.9
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

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- ``ipv4only.arpa`` is now served when ``dns64`` is configured. [GL #385]

- It is now possible to transition a zone from secure to insecure mode
  without making it bogus in the process: changing to ``dnssec-policy
  none;`` also causes CDS and CDNSKEY DELETE records to be published, to
  signal that the entire DS RRset at the parent must be removed, as
  described in RFC 8078. [GL #1750]

- The default value of ``max-stale-ttl`` has been changed from 12 hours to 1
  day and the default value of ``stale-answer-ttl`` has been changed from 1
  second to 30 seconds, following RFC 8767 recommendations. [GL #2248]

- When using the ``unixtime`` or ``date`` method to update the SOA
  serial number, ``named`` and ``dnssec-signzone`` silently fell back to
  the ``increment`` method to prevent the new serial number from being
  smaller than the old serial number (using serial number arithmetics).
  ``dnsssec-signzone`` now prints a warning message, and ``named`` logs
  a warning, when such a fallback happens. [GL #2058]

Bug Fixes
~~~~~~~~~

- Only assign threads to CPUs in the CPU affinity set, so that ``named`` no
  longer attempts to run threads on CPUs outside the affinity set. Thanks to
  Ole Bjørn Hessen. [GL #2245]

- When reconfiguring ``named``, removing ``auto-dnssec`` did actually not turn
  off DNSSEC maintenance. This has been fixed. [GL #2341]

- Prevent rbtdb instances being destroyed by multiple threads at the same
  time. This can trigger assertion failures. [GL #2355]
