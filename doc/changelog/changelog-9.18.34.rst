.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

BIND 9.18.34
------------

New Features
~~~~~~~~~~~~

- Print the expiration time of the stale records. ``f04168545d1``

  Print the expiration time of the stale RRsets in the cache dump.
  :gl:`!10062`

Removed Features
~~~~~~~~~~~~~~~~

- Remove --with-tuning=small/large configuration option. ``327b666c6d0``

  The configuration option --with-tuning has been removed as it is no
  longer required or desired. :gl:`!9959`

Feature Changes
~~~~~~~~~~~~~~~

- Reduce memory sizes of common structures. ``008e5201098``

  * Reduce `sizeof(isc_sockaddr_t)` from 152 to 48 bytes
  * Reduce `sizeof(struct isc__nm_uvreq)` from 1560 to 560 bytes

  Partial backport of !8299 :gl:`!9953`

- Refactor reference counting in RBTDB. ``fd9a85addc4``

  Clean up the pattern in the newref() and decref() functions in RBTDB
  databases.

  Related to #5134 :gl:`!10036`

- Shutdown the fetch context after canceling the last fetch.
  ``57187b2c4f4``

  Shutdown the fetch context immediately after the last fetch has been
  canceled from that particular fetch context. :gl:`!9960`

Bug Fixes
~~~~~~~~~

- Fix "rndc flushname" for longer name server names. ``b7383e50484``

  :option:`rndc flushname` did not work for name server names longer
  than 16 bytes. This has been fixed. :gl:`#3885` :gl:`!10025`

- Recently expired records could be returned with timestamp in future.
  ``4c49d99d560``

  Under rare circumstances, the RRSet that expired at the time of the
  query could be returned with TTL far in the future.  This has been
  fixed.

  As a side-effect, the expiration time of expired RRSets are no longer
  printed out in the cache dump. :gl:`#5094` :gl:`!10060`

- Yaml string not terminated in negative response in delv.
  ``132947c0bad``

  :gl:`#5098` :gl:`!9980`

- Apply the memory limit only to ADB database items. ``7c90bd5bb3d``

  Resolver under heavy-load could exhaust the memory available for
  storing the information in the Address Database (ADB) effectively
  evicting already stored information in the ADB.  The memory used to
  retrieve and provide information from the ADB is now not a subject of
  the same memory limits that are applied for storing the information in
  the Address Database. :gl:`#5127` :gl:`!9976`

- Avoid unnecessary locking in the zone/cache database. ``43c77d95f1d``

  Prevent lock contention among many worker threads referring to the
  same database node at the same time. This would improve zone and cache
  database performance for the heavily contended database nodes.
  :gl:`#5130` :gl:`!9965`

- Fix the cache findzonecut() implementation. ``368315b3c7e``

  The search for the deepest known zone cut in the cache could
  improperly reject a node if it contained any stale data, regardless of
  whether it was the NS RRset that was stale. :gl:`#5155` :gl:`!10051`

- Improve the resolver performance under attack. ``2c667bc9c61``

  A remote client can force the DNS resolver component to consume the
  memory faster than cleaning up the resources for the canceled resolver
  fetches due to `recursive-clients` limit. If the such traffic pattern
  is sustained for a long period of time, the DNS server might
  eventually run out of the available memory. This has been fixed.

  It should be noted that when under such heavy attack for BIND 9
  version both with and without the fix, no outgoing DNS queries will be
  successful as the generated traffic pattern will consume all the
  available slots for the recursive clients. :gl:`!9961`


