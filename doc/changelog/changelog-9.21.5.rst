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

BIND 9.21.5
-----------

New Features
~~~~~~~~~~~~

- Adds support for EDE code 1 and 2. ``5a8fce4851b``

  Add support for EDE codes 1 & 2 which might occurs during DNSSEC
  validation in case of unsupported RRSIG algorithm or DNSKEY digest.
  :gl:`#2715` :gl:`!9948`

- Add a rndc command to toggle jemalloc profiling. ``2bee113a467``

  The new command is `rndc memprof`. The memory profiling status is also
  reported inside `rndc status`. The status also shows whether named can
  toggle memory profiling or not and if the server is built with
  jemalloc. :gl:`#4759` :gl:`!9370`

- Add support for multiple extended DNS errors. ``076e47b4277``

  Extended DNS error mechanism (EDE) may have several errors raised
  during a DNS resolution. `named` is now able to add up to three EDE
  codes in a DNS response. In the case of duplicate error codes, only
  the first one will be part of the DNS response. :gl:`#5085`
  :gl:`!9952`

- Print the expiration time of the stale records. ``ae73ac81a3a``

  Print the expiration time of the stale RRsets in the cache dump.
  :gl:`!10057`

Removed Features
~~~~~~~~~~~~~~~~

- Clean up unused result codes. ``d3455be08c9``

  A number of result codes are obsolete and can be removed. Others,
  including `ISC_R_NOMEMORY`, are still checked in various places even
  though they can't occur any longer. These have been cleaned up.
  :gl:`!9942`

- Remove fields from struct fetchctx. ``1732346fcc3``

  struct fetchctx does have several fields which are now unused or
  confusing, removing those. :gl:`!9945`

Feature Changes
~~~~~~~~~~~~~~~

- Separate the connect and the read TCP timeouts in dispatch.
  ``3f490fe3fb7``

  The network manager layer has two different timers with their own
  timeout values for TCP connections: connect timeout and read timeout.
  Separate the connect and the read TCP timeouts in the dispatch module
  too. :gl:`#5009` :gl:`!9698`

- Include destination address port number in query logging.
  ``166c3241425``

  When query logging is enabled, named will now include the destination
  address port in the logged message. :gl:`#5060` :gl:`!9972`

- Refactor decref() in both QPDB. ``f43bf94eceb``

  Clean up the pattern in the newref() and decref() functions in QP
  databases.  Replace the `db_nodelock_t` structure with plain reference
  counting for every active database node in QPDB.

  Related to #5134 :gl:`!10006`

- Shutdown the fetch context after canceling the last fetch.
  ``3fe440f0cf9``

  Shutdown the fetch context immediately after the last fetch has been
  canceled from that particular fetch context. :gl:`!9958`

- Use a suitable response in tcp_connected() when initiating a read.
  ``66d4f9184a4``

  When 'ISC_R_TIMEDOUT' is received in 'tcp_recv()', it times out the
  oldest response in the active responses queue, and only after that it
  checks whether other active responses have also timed out. So when
  setting a timeout value for a read operation after a successful
  connection, it makes sense to take the timeout value from the oldest
  response in the active queue too, because, theoretically, the
  responses can have different timeout values, e.g. when the TCP
  dispatch is shared. Currently 'resp' is always NULL. Previously when
  connect and read timeouts were not separated in dispatch this affected
  only logging, but now since we are setting a new timeout after a
  successful connection, we need to choose a suitable response from the
  active queue. :gl:`!9927`

Bug Fixes
~~~~~~~~~

- Fix possible truncation in dns_keymgr_status() ``eec0aaa391e``

  If the generated status output exceeds 4096 it was silently truncated,
  now we output that the status was truncated. :gl:`#4180` :gl:`!9905`

- Validate adb fetches. ``d9eb272b690``

  ADB responses were not being validated, allowing spoofed responses to
  be accepted and used for further lookups. This should not be possible
  when the servers for the zone are in a signed zone, except with CD=1
  requests or when glue is needed. This has been fixed. :gl:`#5066`
  :gl:`!10052`

- Recently expired records could be returned with timestamp in future.
  ``517c5b6b28b``

  Under rare circumstances, the RRSet that expired at the time of the
  query could be returned with TTL far in the future.  This has been
  fixed.

  As a side-effect, the expiration time of expired RRSets are no longer
  printed out in the cache dump. :gl:`#5094` :gl:`!10048`

- Yaml string not terminated in negative response in delv.
  ``e57ebb8f1b4``

  :gl:`#5098` :gl:`!9922`

- Fix a bug in dnssec-signzone related to keys being offline.
  ``8efb4e2f26a``

  In the case when `dnssec-signzone` is called on an already signed
  zone, and the private key file is unavailable, a signature that needs
  to be refreshed may be dropped without being able to generate a
  replacement. This has been fixed. :gl:`#5126` :gl:`!9951`

- Apply the memory limit only to ADB database items. ``0673568c170``

  Resolver under heavy-load could exhaust the memory available for
  storing the information in the Address Database (ADB) effectively
  evicting already stored information in the ADB.  The memory used to
  retrieve and provide information from the ADB is now not a subject of
  the same memory limits that are applied for storing the information in
  the Address Database. :gl:`#5127` :gl:`!9954`

- Avoid unnecessary locking in the zone/cache database. ``48471fd50c7``

  Prevent lock contention among many worker threads referring to the
  same database node at the same time.  This would improve zone and
  cache database performance for the heavily contended database nodes.
  :gl:`#5130` :gl:`!9963`

- Fix EDE 22 time out detection. ``dc3c3efdbf2``

  Extended DNS error 22 (No reachable authority) was previously detected
  when `fctx_expired` fired. It turns out this function is used as a
  "safety net" and the timeout detection should be caught earlier.

  It was working though, because of another issue fixed by !9927. But
  then, the recursive request timed out detection occurs before
  `fctx_expired` making impossible to raise the EDE 22 error.

  This fixes the problem by triggering the EDE 22 in the part of the
  code detecting the (TCP or UDP) time out and taking the decision to
  cancel the whole fetch (i.e. There is no other server to attempt to
  contact).

  Note this is not targeting users (no release note) because there is no
  release versions of BIND between !9927 and this changes. Thus a
  release note would be confusing. :gl:`#5137` :gl:`!9985`

- Split and simplify the use of EDE list implementation. ``a8e0a695c48``

  Instead of mixing the dns_resolver and dns_validator units directly
  with the EDE code, split-out the dns_ede functionality into own
  separate compilation unit and hide the implementation details behind
  abstraction.

  Additionally, the new dns_edelist_t doesn't have to be copied into all
  responses as those are attached to the fetch context, but it could be
  only passed by reference.

  This makes the dns_ede implementation simpler to use, although sligtly
  more complicated on the inside. :gl:`#5141` :gl:`!10016`

- Fix the cache findzonecut() implementation. ``282b0ed5140``

  The search for the deepest known zone cut in the cache could
  improperly reject a node if it contained any stale data, regardless of
  whether it was the NS RRset that was stale. :gl:`#5155` :gl:`!10047`

- DNSSEC EDE system tests on FIPS platform. ``fd51d80297c``

  Changes introducing the support of extended DNS error code 1 and 2
  uses SHA-1 digest for some tests which break FIPS platform. The digest
  itself was irrelevant, another digest is used. :gl:`!10002`

- Reduce the false sharing the dns_qpcache and dns_qpzone.
  ``d4a7bff0b62``

  Instead of having many node_lock_count * sizeof(<member>) arrays, pack
  all the members into a qpcache_bucket_t that is cacheline aligned to
  prevent false sharing between RWLocks. :gl:`!10072`


