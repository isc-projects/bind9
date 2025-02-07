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

Notes for BIND 9.20.6
---------------------

New Features
~~~~~~~~~~~~

- Adds support for EDE code 1 and 2.

  Add support for EDE codes 1 & 2 which might occurs during DNSSEC
  validation in case of unsupported RRSIG algorithm or DNSKEY digest.
  :gl:`#2715`

- Add a rndc command to toggle jemalloc profiling.

  The new command is `rndc memprof`. The memory profiling status is also
  reported inside `rndc status`. The status also shows whether named can
  toggle memory profiling or not and if the server is built with
  jemalloc. :gl:`#4759`

- Add support for multiple extended DNS errors.

  Extended DNS error mechanism (EDE) may have several errors raised
  during a DNS resolution. `named` is now able to add up to three EDE
  codes in a DNS response. In the case of duplicate error codes, only
  the first one will be part of the DNS response. :gl:`#5085`

- Print the expiration time of the stale records.

  Print the expiration time of the stale RRsets in the cache dump.

Bug Fixes
~~~~~~~~~

- Recently expired records could be returned with timestamp in future.

  Under rare circumstances, the RRSet that expired at the time of the
  query could be returned with TTL far in the future.  This has been
  fixed.

  As a side-effect, the expiration time of expired RRSets are no longer
  printed out in the cache dump. :gl:`#5094`

- Yaml string not terminated in negative response in delv.

  :gl:`#5098`

- Fix a bug in dnssec-signzone related to keys being offline.

  In the case when `dnssec-signzone` is called on an already signed
  zone, and the private key file is unavailable, a signature that needs
  to be refreshed may be dropped without being able to generate a
  replacement. This has been fixed. :gl:`#5126`

- Apply the memory limit only to ADB database items.

  Resolver under heavy-load could exhaust the memory available for
  storing the information in the Address Database (ADB) effectively
  evicting already stored information in the ADB.  The memory used to
  retrieve and provide information from the ADB is now not a subject of
  the same memory limits that are applied for storing the information in
  the Address Database. :gl:`#5127`

- Avoid unnecessary locking in the zone/cache database.

  Prevent lock contention among many worker threads referring to the
  same database node at the same time. This would improve zone and cache
  database performance for the heavily contended database nodes.
  :gl:`#5130`


