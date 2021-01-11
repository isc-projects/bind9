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

- It is now possible to transition a zone from secure to insecure mode
  without making it bogus in the process; changing to ``dnssec-policy
  none;`` also causes CDS and CDNSKEY DELETE records to be published, to
  signal that the entire DS RRset at the parent must be removed, as
  described in RFC 8078. [GL #1750]

- When using the ``unixtime`` or ``date`` method to update the SOA
  serial number, ``named`` and ``dnssec-signzone`` silently fell back to
  the ``increment`` method to prevent the new serial number from being
  smaller than the old serial number (using serial number arithmetics).
  ``dnssec-signzone`` now prints a warning message, and ``named`` logs a
  warning, when such a fallback happens. [GL #2058]

- As part of an ongoing effort to use RFC 8499 terminology,
  ``primaries`` can now be used as a synonym for ``masters`` in
  ``named.conf``. Similarly, ``notify primary-only`` can now be used as
  a synonym for ``notify master-only``. The output of ``rndc
  zonestatus`` now uses ``primary`` and ``secondary`` terminology.
  [GL #1948]

Bug Fixes
~~~~~~~~~

- Multiple threads could attempt to destroy a single RBTDB instance at
  the same time, resulting in an unpredictable but low-probability
  assertion failure in ``free_rbtdb()``. This has been fixed. [GL #2317]

- ``named`` no longer attempts to assign threads to CPUs outside the CPU
  affinity set. Thanks to Ole Bjørn Hessen. [GL #2245]

- When reconfiguring ``named``, removing ``auto-dnssec`` did not turn
  off DNSSEC maintenance. This has been fixed. [GL #2341]

- The report of intermittent BIND assertion failures triggered in
  ``lib/dns/resolver.c:dns_name_issubdomain()`` has now been closed
  without further action. Our initial response to this was to add
  diagnostic logging instead of terminating ``named``, anticipating that
  we would receive further useful troubleshooting input. This workaround
  first appeared in BIND releases 9.17.5 and 9.16.7. However, since
  those releases were published, there have been no new reports of
  assertion failures matching this issue, but also no further diagnostic
  input, so we have closed the issue. [GL #2091]

- KASP incorrectly set signature validity to the value of the DNSKEY signature
  validity. This is now fixed. [GL #2383]
