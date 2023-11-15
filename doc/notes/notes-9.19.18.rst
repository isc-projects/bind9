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

Notes for BIND 9.19.18
----------------------

New Features
~~~~~~~~~~~~

- The statistics channel now includes information about incoming zone
  transfers that are currently in progress. :gl:`#3883`

- The new :any:`resolver-use-dns64` option enables :iscman:`named` to
  apply :any:`dns64` rules to IPv4 server addresses when sending
  recursive queries, so that resolution can be performed over a NAT64
  connection. :gl:`#608`

Removed Features
~~~~~~~~~~~~~~~~

- Support for the ``lock-file`` statement and the ``named -X``
  command-line option has been removed. An external process supervisor
  should be used instead. :gl:`#4391`

  Alternatively, the ``flock`` utility (part of util-linux) can be used
  on Linux systems to achieve the same effect as ``lock-file`` or
  ``named -X``:

  ::

    flock -n -x <directory>/named.lock <path>/named <arguments>

- Configuring the control channel to use a Unix domain socket has been a
  fatal error since BIND 9.18. The feature has now been completely
  removed and :iscman:`named-checkconf` now reports it as a
  configuration error. :gl:`#4311`

Feature Changes
~~~~~~~~~~~~~~~

- Processing large incremental transfers (IXFR) has been offloaded to a
  separate work thread so that it does not prevent networking threads
  from processing regular traffic in the meantime. :gl:`#4367`

- QNAME minimization is now used when looking up the addresses of name
  servers during the recursive resolution process. :gl:`#4209`

- The :any:`inline-signing` zone option is now ignored if there is no
  :any:`dnssec-policy` configured for the zone. This means that unsigned
  zones no longer create redundant signed versions of the zone.
  :gl:`#4349`

- The IP addresses for B.ROOT-SERVERS.NET have been updated to
  170.247.170.2 and 2801:1b8:10::b. :gl:`#4101`

Bug Fixes
~~~~~~~~~

- :any:`max-cache-size` accidentally became ineffective in BIND 9.19.16.
  This has been fixed and the option now behaves as documented again.
  :gl:`#4340`

- If the unsigned version of an inline-signed zone contained DNSSEC
  records, it was incorrectly scheduled for resigning. This has been
  fixed. :gl:`#4350`

- Looking up stale data from the cache did not take local authoritative
  data into account. This has been fixed. :gl:`#4355`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
