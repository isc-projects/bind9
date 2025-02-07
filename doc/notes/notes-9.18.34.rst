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

Notes for BIND 9.18.34
----------------------

New Features
~~~~~~~~~~~~

- Print the expiration time of the stale records.

  Print the expiration time of the stale RRsets in the cache dump.

Removed Features
~~~~~~~~~~~~~~~~

- Remove `--with-tuning=small/large` configuration option.

  The configuration option `--with-tuning` has been removed as it is no
  longer required or desired.

Bug Fixes
~~~~~~~~~

- Fix :iscman:`rndc flushname` for longer name server names.

  :option:`rndc flushname` did not work for name server names longer
  than 16 bytes. This has been fixed. :gl:`#3885`

- Recently expired records could be returned with timestamp in future.

  Under rare circumstances, the RRSet that expired at the time of the
  query could be returned with TTL far in the future.  This has been
  fixed.

  As a side-effect, the expiration time of expired RRSets are no longer
  printed out in the cache dump. :gl:`#5094`

- Yaml string not terminated in negative response in delv.

  :gl:`#5098`

- Apply the memory limit only to ADB database items.

  The resolver under heavy-load could exhaust the memory available for
  storing the information in the Address Database (ADB) effectively
  evicting already stored information in the ADB.  The memory used to
  retrieve and provide information from the ADB is now not a subject of
  the same memory limits that are applied for storing the information in
  the Address Database. :gl:`#5127`

- Avoid unnecessary locking in the zone/cache database.

  Prevent lock contention among many worker threads referring to the
  same database node at the same time. This improves zone and cache
  database performance for the heavily contended database nodes.
  :gl:`#5130`

- Improve the resolver performance under attack.

  A remote client can force the DNS resolver component to consume the
  memory faster than cleaning up the resources for the canceled resolver
  fetches due to `recursive-clients` limit. If the such traffic pattern
  is sustained for a long period of time, the DNS server might
  eventually run out of the available memory. This has been fixed.

  It should be noted that when under such heavy attack for a BIND 9
  version both with and without the fix, no outgoing DNS queries will be
  successful as the generated traffic pattern will consume all the
  available slots for the recursive clients.


