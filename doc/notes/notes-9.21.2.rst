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

(-dev)
------

New Features
~~~~~~~~~~~~

- Log query response status to the query log.

  Log a query response summary using the new category `responses`.
  Logging can be controlled by the option `responselog` and `rndc
  responselog`. :gl:`#459`

- Added WALLET type.

  Add the new record type WALLET (262).  This provides a mapping from a
  domain name to a cryptographic currency wallet.  Multiple mappings can
  exist if multiple records exist. :gl:`#4947`

- Support ISO timestamps with timezone information.

  The configuration option `print-time` can now be set to
  `iso8601-tzinfo` in order to use the ISO 8601 timestamp with timezone
  information when logging. This is used as a default for `named -g`.
  :gl:`#4963`

- Add flag to named-checkconf to ignore "not configured" errors.

  `named-checkconf` now takes "-n" to ignore "not configured" errors.
  This allows named-checkconf to check the syntax of configurations from
  other builds which have support for more options.

- Implement the ForwardOnlyFail statistics channel counter.

  The new ForwardOnlyFail statistics channel counter indicates the
  number of queries failed due to bad forwarders for 'forward only'
  zones.

  Related to #1793

Removed Features
~~~~~~~~~~~~~~~~

- Remove "port" from source address options.

  Remove the use of "port" when configuring query-source(-v6), transfer-
  source(-v6), notify-source(-v6), parental-source(-v6), etc. Remove the
  use of source ports for parental-agents.

  Also remove the deprecated options use-{v4,v6}-udp-ports and
  avoid-{v4,v6}udp-ports. :gl:`#3843`

- Remove DNSRPS implementation from the open-source version.

  DNSRPS was the API for a commercial implementation of Response-Policy
  Zones that was supposedly better.  However, it was never open-sourced
  and has only ever been available from a single vendor.  This goes
  against the principle that the open-source edition of BIND 9 should
  contain only features that are generally available and universal.

  This commit removes the DNSRPS implementation from BIND 9.  It may be
  reinstated in the subscription edition if there's enough interest from
  customers, but it would have to be rewritten as a plugin (hook)
  instead of hard-wiring it again in so many places.

Feature Changes
~~~~~~~~~~~~~~~

- Set logging category for notify/xfer-in related messages.

  Some 'notify' and 'xfer-in' related log messages were logged at the
  'general' category instead of their own category. This has been fixed.
  :gl:`#2730`

- Allow IXFR-to-AXFR fallback on DNS_R_TOOMANYRECORDS.

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

- Honour the Control Group memory contraints on Linux.

  On Linux, the system administrator can use Control Group ``cgroup``
  mechanism to limit the amount of available memory to the process.
  This limit will be honoured when calculating the percentage-based
  values.

Bug Fixes
~~~~~~~~~

- Fix a statistics channel counter bug when 'forward only' zones are
  used.

  When resolving a zone with a 'forward only' policy, and finding out
  that all the forwarders are marked as "bad", the 'ServerQuota' counter
  of the statistics channel was incorrectly increased. This has been
  fixed. :gl:`#1793`

- Fix a bug in the static-stub implementation.

  Static-stub addresses and addresses from other sources were being
  mixed together, resulting in static-stub queries going to addresses
  not specified in the configuration, or alternatively, static-stub
  addresses being used instead of the correct server addresses.
  :gl:`#4850`

- Don't allow statistics-channel if libxml2 and libjson-c are
  unsupported.

  When the libxml2 and libjson-c libraries are not supported, the
  statistics channel can't return anything useful, so it is now
  disabled. Use of `statistics-channel` in `named.conf` is a fatal
  error. :gl:`#4895`

- Separate DNSSEC validation from the long-running tasks.

  As part of the KeyTrap \[CVE-2023-50387\] mitigation, the DNSSEC CPU-
  intensive operations were offloaded to a separate threadpool that we
  use to run other tasks that could affect the networking latency.

  If that threadpool is running some long-running tasks like RPZ,
  catalog zone processing, or zone file operations, it would delay
  DNSSEC validations to a point where the resolving signed DNS records
  would fail.

  Split the CPU-intensive and long-running tasks into separate
  threadpools in a way that the long-running tasks don't block the CPU-
  intensive operations. :gl:`#4898`

- Fix assertion failure when processing access control lists.

  The named process could terminate unexpectedly when processing ACL.
  This has been fixed. :gl:`#4908`

- Fix bug in Offline KSK that is using ZSK with unlimited lifetime.

  If the ZSK has unlimited lifetime, the timing metadata "Inactive" and
  "Delete" cannot be found and is treated as an error, preventing the
  zone to be signed. This has been fixed. :gl:`#4914`

- Limit the outgoing UDP send queue size.

  If the operating system UDP queue gets full and the outgoing UDP
  sending starts to be delayed, BIND 9 could exhibit memory spikes as it
  tries to enqueue all the outgoing UDP messages.  Try a bit harder to
  deliver the outgoing UDP messages synchronously and if that fails,
  drop the outgoing DNS message that would get queued up and then
  timeout on the client side. :gl:`#4930`

- Do not set SO_INCOMING_CPU.

  We currently set SO_INCOMING_CPU incorrectly, and testing by Ondrej
  shows that fixing the issue by setting affinities is worse than
  letting the kernel schedule threads without constraints. So we should
  not set SO_INCOMING_CPU anymore. :gl:`#4936`

- Fix the 'rndc dumpdb' command's error reporting.

  The 'rndc dumpdb' command wasn't reporting errors which occurred when
  starting up the database dump process by named, like, for example, a
  permission denied error for the 'dump-file' file. This has been fixed.
  Note, however, that 'rndc dumpdb' performs asynchronous writes, so
  errors can also occur during the dumping process, which will not be
  reported back to 'rndc', but which will still be logged by named.
  :gl:`#4944`

- Fix long-running incoming transfers.

  Incoming transfers that took longer than 30 seconds would stop reading
  from the TCP stream and the incoming transfer would be indefinitely
  stuck causing BIND 9 to hang during shutdown.

  This has been fixed and the `max-transfer-time-in` and `max-transfer-
  idle-in` timeouts are now honoured. :gl:`#4949`

- Fix assertion failure when receiving DNS responses over TCP.

  When matching the received Query ID in the TCP connection, an invalid
  received Query ID can very rarely cause assertion failure. :gl:`#4952`


