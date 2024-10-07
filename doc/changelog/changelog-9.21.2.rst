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

BIND 9.21.2
-----------

New Features
~~~~~~~~~~~~

- Log query response status to the query log. ``a4b9625196d``

  Log a query response summary using the new category `responses`.
  Logging can be controlled by the option `responselog` and `rndc
  responselog`. :gl:`#459` :gl:`!9449`

- Added WALLET type. ``d0d4c6dae72``

  Add the new record type WALLET (262).  This provides a mapping from a
  domain name to a cryptographic currency wallet.  Multiple mappings can
  exist if multiple records exist. :gl:`#4947` :gl:`!9521`

- Support ISO timestamps with timezone information. ``e618cdddf8f``

  The configuration option `print-time` can now be set to
  `iso8601-tzinfo` in order to use the ISO 8601 timestamp with timezone
  information when logging. This is used as a default for `named -g`.
  :gl:`#4963` :gl:`!9563`

- Add flag to named-checkconf to ignore "not configured" errors.
  ``0d2482c62e9``

  `named-checkconf` now takes "-n" to ignore "not configured" errors.
  This allows named-checkconf to check the syntax of configurations from
  other builds which have support for more options. :gl:`!9446`

- Implement the ForwardOnlyFail statistics channel counter.
  ``3efa17ee014``

  The new ForwardOnlyFail statistics channel counter indicates the
  number of queries failed due to bad forwarders for 'forward only'
  zones.

  Related to #1793 :gl:`!9498`

Removed Features
~~~~~~~~~~~~~~~~

- Remove "port" from source address options. ``dc3578ee84c``

  Remove the use of "port" when configuring query-source(-v6), transfer-
  source(-v6), notify-source(-v6), parental-source(-v6), etc. Remove the
  use of source ports for parental-agents.

  Also remove the deprecated options use-{v4,v6}-udp-ports and
  avoid-{v4,v6}udp-ports. :gl:`#3843` :gl:`!9469`

- Remove DNSRPS implementation from the open-source version.
  ``20024a28c01``

  DNSRPS was the API for a commercial implementation of Response-Policy
  Zones that was supposedly better.  However, it was never open-sourced
  and has only ever been available from a single vendor.  This goes
  against the principle that the open-source edition of BIND 9 should
  contain only features that are generally available and universal.

  This commit removes the DNSRPS implementation from BIND 9.  It may be
  reinstated in the subscription edition if there's enough interest from
  customers, but it would have to be rewritten as a plugin (hook)
  instead of hard-wiring it again in so many places. :gl:`!9358`

- Remove unused function dns_zonemgr_resumexfrs() ``4d759a251b9``

  :gl:`!9565`

Feature Changes
~~~~~~~~~~~~~~~

- Set logging category for notify/xfer-in related messages.
  ``796f8861735``

  Some 'notify' and 'xfer-in' related log messages were logged at the
  'general' category instead of their own category. This has been fixed.
  :gl:`#2730` :gl:`!9451`

- Restore the number of threadpool threads back to original value.
  ``28badd8ed48``

  The issue of long-running operations potentially blocking query
  resolution has been fixed. Revert this temporary workaround and
  restore the number of threadpool threads. :gl:`#4898` :gl:`!9530`

- Allow IXFR-to-AXFR fallback on DNS_R_TOOMANYRECORDS. ``b343484ddb6``

  This change allows fallback from an IXFR failure to AXFR when the
  reason is `DNS_R_TOOMANYRECORDS`. This is because this error condition
  could be temporary only in an intermediate version of IXFR
  transactions and it's possible that the latest version of the zone
  doesn't have that condition. In such a case, the secondary would never
  be able to update the zone (even if it could) without this fallback.

  This fallback behavior is particularly useful with the recently
  introduced `max-records-per-type` and `max-types-per-name` options:
  the primary may not have these limitations and may temporarily
  introduce "too many" records, breaking IXFR. If the primary side
  subsequently deletes these records, this fallback will help recover
  the zone transfer failure automatically; without it, the secondary
  side would first need to increase the limit, which requires more
  operational overhead and has its own adverse effect. :gl:`#4928`
  :gl:`!9333`

- Remove statslock from dnssec-signzone. ``f466e32fdb1``

  Silence Coverity CID 468757 and 468767 (DATA RACE read not locked) by
  converting dnssec-signzone to use atomics for statistics counters
  rather than using a lock. :gl:`#4939` :gl:`!9496`

- Honour the Control Group memory contraints on Linux. ``f48b86871f4``

  On Linux, the system administrator can use Control Group ``cgroup``
  mechanism to limit the amount of available memory to the process.
  This limit will be honoured when calculating the percentage-based
  values. :gl:`!9556`

- Use libuv functions to get memory available to BIND 9. ``aed7f552d54``

  This change uses uv_get_available_memory() if available with fallback
  to uv_get_constrained_memory() with fallback to uv_get_total_memory().
  :gl:`!9527`

- Use release memory ordering when incrementing reference counter.
  ``b1be0145a5a``

  As the relaxed memory ordering doesn't ensure any memory
  synchronization, it is possible that the increment will succeed even
  in the case when it should not - there is a race between
  atomic_fetch_sub(..., acq_rel) and atomic_fetch_add(..., relaxed).
  Only the result is consistent, but the previous value for both calls
  could be same when both calls are executed at the same time.
  :gl:`!9460`

- Use uv_available_parallelism() if available. ``59e85a022da``

  Instead of cooking up our own code for getting the number of available
  CPUs for named to use, make use of uv_available_parallelism() from
  libuv >= 1.44.0. :gl:`!9524`

Bug Fixes
~~~~~~~~~

- Fix a statistics channel counter bug when 'forward only' zones are
  used. ``b82957376dc``

  When resolving a zone with a 'forward only' policy, and finding out
  that all the forwarders are marked as "bad", the 'ServerQuota' counter
  of the statistics channel was incorrectly increased. This has been
  fixed. :gl:`#1793` :gl:`!9493`

- Fix a bug in the static-stub implementation. ``3304e1dc769``

  Static-stub addresses and addresses from other sources were being
  mixed together, resulting in static-stub queries going to addresses
  not specified in the configuration, or alternatively, static-stub
  addresses being used instead of the correct server addresses.
  :gl:`#4850` :gl:`!9314`

- Don't allow statistics-channel if libxml2 and libjson-c are
  unsupported. ``0d4accd07f4``

  When the libxml2 and libjson-c libraries are not supported, the
  statistics channel can't return anything useful, so it is now
  disabled. Use of `statistics-channel` in `named.conf` is a fatal
  error. :gl:`#4895` :gl:`!9423`

- Separate DNSSEC validation from the long-running tasks.
  ``23b2ce56e5d``

  As part of the KeyTrap \[CVE-2023-50387\] mitigation, the DNSSEC CPU-
  intensive operations were offloaded to a separate threadpool that we
  use to run other tasks that could affect the networking latency.

  If that threadpool is running some long-running tasks like RPZ,
  catalog zone processing, or zone file operations, it would delay
  DNSSEC validations to a point where the resolving signed DNS records
  would fail.

  Split the CPU-intensive and long-running tasks into separate
  threadpools in a way that the long-running tasks don't block the CPU-
  intensive operations. :gl:`#4898` :gl:`!9473`

- Fix assertion failure when processing access control lists.
  ``6bb4070685c``

  The named process could terminate unexpectedly when processing ACL.
  This has been fixed. :gl:`#4908` :gl:`!9458`

- Fix bug in Offline KSK that is using ZSK with unlimited lifetime.
  ``3e11c4a8733``

  If the ZSK has unlimited lifetime, the timing metadata "Inactive" and
  "Delete" cannot be found and is treated as an error, preventing the
  zone to be signed. This has been fixed. :gl:`#4914` :gl:`!9447`

- Fix data race in offloaded dns_message_checksig() ``3808567de1a``

  When verifying a message in an offloaded thread there is a race with
  the worker thread which writes to the same buffer. Clone the message
  buffer before offloading. :gl:`#4929` :gl:`!9481`

- Limit the outgoing UDP send queue size. ``3b26732781c``

  If the operating system UDP queue gets full and the outgoing UDP
  sending starts to be delayed, BIND 9 could exhibit memory spikes as it
  tries to enqueue all the outgoing UDP messages.  Try a bit harder to
  deliver the outgoing UDP messages synchronously and if that fails,
  drop the outgoing DNS message that would get queued up and then
  timeout on the client side. :gl:`#4930` :gl:`!9506`

- Do not set SO_INCOMING_CPU. ``f93934dea76``

  We currently set SO_INCOMING_CPU incorrectly, and testing by Ondrej
  shows that fixing the issue by setting affinities is worse than
  letting the kernel schedule threads without constraints. So we should
  not set SO_INCOMING_CPU anymore. :gl:`#4936` :gl:`!9497`

- Fix the 'rndc dumpdb' command's error reporting. ``4498c0216f1``

  The 'rndc dumpdb' command wasn't reporting errors which occurred when
  starting up the database dump process by named, like, for example, a
  permission denied error for the 'dump-file' file. This has been fixed.
  Note, however, that 'rndc dumpdb' performs asynchronous writes, so
  errors can also occur during the dumping process, which will not be
  reported back to 'rndc', but which will still be logged by named.
  :gl:`#4944` :gl:`!9547`

- Fix long-running incoming transfers. ``f0accc8f617``

  Incoming transfers that took longer than 30 seconds would stop reading
  from the TCP stream and the incoming transfer would be indefinitely
  stuck causing BIND 9 to hang during shutdown.

  This has been fixed and the `max-transfer-time-in` and `max-transfer-
  idle-in` timeouts are now honoured. :gl:`#4949` :gl:`!9531`

- Fix assertion failure when receiving DNS responses over TCP.
  ``fe305f96c9c``

  When matching the received Query ID in the TCP connection, an invalid
  received Query ID can very rarely cause assertion failure. :gl:`#4952`
  :gl:`!9580`

- Null clausedefs for ancient options. ``474398a5a99``

  This commit nulls all type fields for the clausedef lists that are
  declared ancient, and removes the corresponding cfg_type_t and parsing
  functions when they are found to be unused after the change.

  Among others, it removes some leftovers from #1913. :gl:`#4962`
  :gl:`!9552`

- Don't ignore the local port number in dns_dispatch_add() for TCP.
  ``41f4c620c2e``

  The dns_dispatch_add() function registers the 'resp' entry in
  'disp->mgr->qids' hash table with 'resp->port' being 0, but in
  tcp_recv_success(), when looking up an entry in the hash table after a
  successfully received data the port is used, so if the local port was
  set (i.e. it was not 0) it fails to find the entry and results in an
  unexpected error.

  Set the 'resp->port' to the given local port value extracted from
  'disp->local'. :gl:`#4969` :gl:`!9576`

- Add a missing rcu_read_unlock() call on exit path. ``d7d1804f16e``

  An exit path in the dns_dispatch_add() function fails to get out of
  the RCU critical section when returning early. Add the missing
  rcu_read_unlock() call. :gl:`!9561`

- Clean up DNSRPS. ``4187ef28e2c``

  Addressed several build and test errors when DNSRPS is enabled.
  :gl:`!9374`

- Don't enable REUSEADDR on outgoing UDP sockets. ``27c4d7ef6d9``

  The outgoing UDP sockets enabled `SO_REUSEADDR` that allows sharing of
  the UDP sockets, but with one big caveat - the socket that was opened
  the last would get all traffic.  The dispatch code would ignore the
  invalid responses in the dns_dispatch, but this could lead to
  unexpected results. :gl:`!9569`


