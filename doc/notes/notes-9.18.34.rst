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

- Fix :option:`rndc flushname` for longer name server names.

  :option:`rndc flushname` did not work for name server names longer
  than 16 bytes. This has been fixed. :gl:`#3885`

- Recently expired records could be returned with a timestamp in future.

  Under rare circumstances, an RRSet that expired at the time of the
  query could be returned with a TTL in the future. This has been fixed.

  As a side effect, the expiration time of expired RRSets is no longer
  returned in a cache dump. :gl:`#5094`

- YAML string not terminated in negative response in delv.

  :gl:`#5098`

- Apply the memory limit only to ADB database items.

  Under heavy load, a resolver could exhaust the memory available for
  storing the information in the Address Database (ADB), effectively
  discarding previously stored information in the ADB. The memory used to
  retrieve and provide information from the ADB is no longer subject to
  the same memory limits that are applied to


  the Address Database. :gl:`#5127`

- Avoid unnecessary locking in the zone/cache database.

  Lock contention among many worker threads referring to the
  same database node at the same time is now prevented. This improves zone and
  cache database performance for any heavily contended database nodes.
  :gl:`#5130`

- Improve the resolver performance under attack.

  Previously, a remote client could force the DNS resolver component to consume
  memory faster than resources were cleaned up for the canceled resolver
  fetches, due to the `recursive-clients` limit. If such a traffic pattern
  was sustained for a long period of time, the DNS server might
  eventually run out of the available memory. This has been fixed.

  It should be noted that, under such a heavy attack, no outgoing DNS queries will be successful in BIND 9
  versions both with and without the fix, as the generated traffic pattern will consume all the
  available slots for the recursive clients.


