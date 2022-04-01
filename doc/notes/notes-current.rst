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

Notes for BIND 9.18.2
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- Add a new configuration option ``reuseport`` to disable
  load balancing on sockets in scenarios in which processing of
  Response Policy Zones (RPZ), Catalog Zones, or large zone transfers
  can cause service disruptions. See the BIND 9 ARM for more detail.
  :gl:`#3249`

Bug Fixes
~~~~~~~~~

- Invalid dnssec-policy definitions were being accepted where the
  defined keys did not cover both KSK and ZSK roles for a given
  algorithm.  This is now checked for and the dnssec-policy is
  rejected if both roles are not present for all algorithms in use.
  :gl:`#3142`

- Handling of the TCP write timeouts has been improved to track timeout
  for each TCP write separately leading to faster connection tear down
  in case the other party is not reading the data. :gl:`#3200`

- Zone maintenance DNS queries would retry forever while the
  destination server was unreachable. These queries include outgoing
  NOTIFY messages, refresh SOA queries, parental DS checks, and stub
  zone NS queries. For example, if a zone has any nameservers with
  IPv6 addresses and a secondary server without IPv6 connectivity, the
  IPv4-only server would keep trying to send a growing amount of
  NOTIFY traffic over IPv6. This futile traffic was not logged.
  :gl:`#3242`
