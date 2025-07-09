<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

# Per-Loop LRU cleaning

Several compilation units now employ per-loop LRU lists. When combined
with other algorithms, this design allows LRU lists to be lock-free.

When a new entry is created, it is assigned to the currently-running loop
(`isc_tid()`), added to the loop's LRU list, and added to a global
lock-free (`cds_lfht`) hash table.  Deletion of the entry by any loop will
first delete it from the hash table, then schedule it to be removed from
the LRU list by the entry's loop. If LRU cleaning happens in the meantime,
the entry is processed normally.

The badcache and unreachable primaries list are very simple LRUs that don't
update the position of the entry in the list on cache hit; they just
remove the old entry and insert new one.

The ADB combines per-loop LRU lists with the SIEVE algorithm. On a
cache hit, SIEVE marks the entry as "visited". There is no need to
update the LRU list, so an off-loop cache hit is also lock-free.
