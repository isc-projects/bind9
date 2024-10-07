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

- Added WALLET type.

  Add the new record type WALLET (262).  This provides a mapping from a
  domain name to a cryptographic currency wallet.  Multiple mappings can
  exist if multiple records exist. :gl:`#4947`

Feature Changes
~~~~~~~~~~~~~~~

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


