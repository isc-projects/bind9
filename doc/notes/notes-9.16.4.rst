.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.4
---------------------

Security Fixes
~~~~~~~~~~~~~~

-  It was possible to trigger an assertion when attempting to fill an
   oversized TCP buffer. This was disclosed in CVE-2020-8618. [GL #1850]

-  It was possible to trigger an INSIST failure when a zone with an
   interior wildcard label was queried in a certain pattern. This was
   disclosed in CVE-2020-8619. [GL #1111] [GL #1718]

New Features
~~~~~~~~~~~~

-  Documentation was converted from DocBook to reStructuredText. The
   BIND 9 ARM is now generated using Sphinx and published on `Read the
   Docs`_. Release notes are no longer available as a separate document
   accompanying a release. [GL #83]

-  ``named`` and ``named-checkzone`` now reject master zones that
   have a DS RRset at the zone apex.  Attempts to add DS records
   at the zone apex via UPDATE will be logged but otherwise ignored.
   DS records belong in the parent zone, not at the zone apex. [GL #1798]

-  ``dig`` and other tools can now print the Extended DNS Error (EDE)
   option when it appears in a request or response. [GL #1834]

Feature Changes
~~~~~~~~~~~~~~~

-  The default value of ``max-stale-ttl`` has changed from 1 week to 12 hours.
   This option controls how long named retains expired RRsets in cache as a
   potential mitigation mechanism, should there be a problem with one or more
   domains.  Note that cache content retention is independent of whether or not
   stale answers will be used in response to client queries
   (``stale-answer-enable yes|no`` and ``rndc serve-stale on|off``).  Serving of
   stale answers when the authoritative servers are not responding must be
   explicitly enabled, whereas the retention of expired cache content takes
   place automatically on all versions of BIND that have this feature available.
   [GL #1877]

   .. warning:
       This change may be significant for administrators who expect that stale
       cache content will be automatically retained for up to 1 week.  Add
       option ``max-stale-ttl 1w;`` to named.conf to keep the previous behavior
       of named.

-  listen-on-v6 { any; } creates separate sockets for all interfaces,
   while previously it created one socket on systems conforming to
   :rfc:`3493` and :rfc:`3542`, this change was introduced in 9.16.0
   but accudently ommited from documentation.

Bug Fixes
~~~~~~~~~

-  When fully updating the NSEC3 chain for a large zone via IXFR, a
   temporary loss of performance could be experienced on the secondary
   server when answering queries for nonexistent data that required
   DNSSEC proof of non-existence (in other words, queries that required
   the server to find and to return NSEC3 data). The unnecessary
   processing step that was causing this delay has now been removed.
   [GL #1834]

-  ``named`` could crash with an assertion failure if the name of a
   database node was looked up while the database was being modified.
   [GL #1857]

-  A possible deadlock in ``lib/isc/unix/socket.c`` was fixed.
   [GL #1859]

-  Missing mutex and conditional destruction in netmgr code leads to a memory
   leak on BSD systems. [GL #1893].

-  Fix a data race in resolver.c:formerr() that could lead to assertion
   failure. [GL #1808]

-  Previously, ``provide-ixfr no;`` failed to return up-to-date
   responses when the serial number was greater than or equal to the
   current serial number. [GL #1714]

-  Fix a bug in dnssec-policy keymgr where the check if a key has a
   successor would return a false positive if any other key in the
   keyring has a successor. [GL #1845]

-  With dnssec-policy, when creating a successor key, the goal state of
   the current active key (the predecessor) was not changed and thus was
   never is removed from the zone. [GL #1846]

- ``named-checkconf -p`` could include spurious text in
  ``server-addresses`` statements due to an uninitialized DSCP value.
  This has been fixed. [GL #1812]

-  The ARM has been updated to indicate that the TSIG session key is
   generated when named starts, regardless of whether it is needed.
   [GL #1842]

.. _Read the Docs: https://bind9.readthedocs.io/
