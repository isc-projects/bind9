.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.11
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

- It is now possible to transition a zone from secure to insecure mode
  without making it bogus in the process: changing to ``dnssec-policy
  none;`` also causes CDS and CDNSKEY DELETE records to be published, to
  signal that the entire DS RRset at the parent must be removed, as
  described in RFC 8078. [GL #1750]

- The new networking code introduced in BIND 9.16 (netmgr) was
  overhauled in order to make it more stable, testable, and
  maintainable. [GL #2321]

- Earlier releases of BIND versions 9.16 and newer required the
  operating system to support load-balanced sockets in order for
  ``named`` to be able to achieve high performance (by distributing
  incoming queries among multiple threads). However, the only operating
  systems currently known to support load-balanced sockets are Linux and
  FreeBSD 12, which means both UDP and TCP performance were limited to a
  single thread on other systems. As of BIND 9.17.8, ``named`` attempts
  to distribute incoming queries among multiple threads on systems which
  lack support for load-balanced sockets (except Windows). [GL #2137]

- The default value of ``max-stale-ttl`` has been changed from 12 hours to 1
  day and the default value of ``stale-answer-ttl`` has been changed from 1
  second to 30 seconds, following RFC 8767 recommendations. [GL #2248]

- When using the ``unixtime`` or ``date`` method to update the SOA
  serial number, ``named`` and ``dnssec-signzone`` silently fell back to
  the ``increment`` method to prevent the new serial number from being
  smaller than the old serial number (using serial number arithmetics).
  ``dnsssec-signzone`` now prints a warning message, and ``named`` logs
  a warning, when such a fallback happens. [GL #2058]

- As part of an ongoing effort to use RFC 8499 terminology,
  ``primaries`` can now be used as a synonym for ``masters`` in
  ``named.conf``. Similarly, ``notify primary-only`` can now be used as
  a synonym for ``notify master-only``. The output of ``rndc
  zonestatus`` now uses ``primary`` and ``secondary`` terminology.
  [GL #1948]

Bug Fixes
~~~~~~~~~

- When reconfiguring ``named``, removing ``auto-dnssec`` did actually not turn
  off DNSSEC maintenance. This has been fixed. [GL #2341]

- Prevent rbtdb instances being destroyed by multiple threads at the same
  time. This can trigger assertion failures. [GL #2355]

- KASP incorrectly set signature validity to the value of the DNSKEY signature
  validity. This is now fixed. [GL #2383]
