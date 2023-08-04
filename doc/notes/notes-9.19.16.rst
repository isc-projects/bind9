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

Notes for BIND 9.19.16
----------------------

Removed Features
~~~~~~~~~~~~~~~~

- The ``auto-dnssec`` configuration statement has been removed. Please
  use :any:`dnssec-policy` or manual signing instead. The following
  statements have become obsolete: :any:`dnskey-sig-validity`,
  :any:`dnssec-dnskey-kskonly`, :any:`dnssec-update-mode`,
  :any:`sig-validity-interval`, and :any:`update-check-ksk`. :gl:`#3672`

Feature Changes
~~~~~~~~~~~~~~~

- BIND now returns BADCOOKIE for out-of-date or otherwise bad but
  well-formed DNS server cookies. :gl:`#4194`

- When a primary server for a zone responds to an SOA query, but the
  subsequent TCP connection required to transfer the zone is refused,
  that server is marked as temporarily unreachable. This now also
  happens if the TCP connection attempt times out, preventing too many
  zones from queuing up on an unreachable server and allowing the
  refresh process to move on to the next configured primary more
  quickly. :gl:`#4215`

- The :any:`inline-signing` statement can now also be set inside
  :any:`dnssec-policy`. The built-in policies ``default`` and
  ``insecure`` enable the use of :any:`inline-signing`. If
  :any:`inline-signing` is set at the ``zone`` level, it overrides the
  value set in :any:`dnssec-policy`. :gl:`#3677`

- To improve query-processing latency under load, the uninterrupted time
  spent on resolving long chains of cached domain names has been
  reduced. :gl:`#4185`

- The :any:`dialup` and :any:`heartbeat-interval` options have been
  deprecated and will be removed in a future BIND 9 release. :gl:`#3700`

Bug Fixes
~~~~~~~~~

- Setting :any:`dnssec-policy` to ``insecure`` prevented zones
  containing resource records with a TTL value larger than 86400 seconds
  (1 day) from being loaded. This has been fixed by ignoring the TTL
  values in the zone and using a value of 604800 seconds (1 week) as the
  maximum zone TTL in key rollover timing calculations. :gl:`#4032`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
