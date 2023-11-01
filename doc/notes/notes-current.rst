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

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- The statstics channel now includes information about incoming zone transfers
  currently in progress. :gl:`#3883`

- The new :any:`resolver-use-dns64` option enables ``named`` to apply
  :any:`dns64` rules to IPv4 server addresses when sending recursive
  queries, so that resolution can be performed over a NAT64 connection.
  :gl:`#608`

- Processing large incremental transfers (IXFR) can take a long time.
  Offload the processing to a separate work thread that doesn't block
  networking threads and keeps them free to process regular traffic.
  :gl:`#4367`

Removed Features
~~~~~~~~~~~~~~~~

- Configuring control channel to use Unix Domain Socket has an fatal error since
  BIND 9.18.  Completely remove the feature and make ``named-checkconf`` also
  report this as an error in the configuration. :gl:`#4311`

  The support for control channel over Unix Domain Sockets has been
  non-functional since BIND 9.18

- Support for specifying ``lock-file`` via configuration and via the
  :option:`named -X` command line option has been removed. An external process
  supervisor should be used instead.  :gl:`#4391`

  Alternatively :program:`flock` can be used to achieve the same effect as the
  removed configuration/argument:

    flock -n -x <dir>/named.lock <path>/named <args>

Feature Changes
~~~~~~~~~~~~~~~

- The zone option :any:`inline-signing` is now ignored if there is no
  :any:`dnssec-policy` configured for the zone. This means that unsigned
  zones will no longer create redundant signed versions of the zone.
  :gl:`#4349`

- B.ROOT-SERVERS.NET addresses are now 170.247.170.2 and 2801:1b8:10::b.
  :gl:`#4101`

Bug Fixes
~~~~~~~~~

- :any:`max-cache-size` accidentally became ineffective in BIND 9.19.16.
  This has been fixed and the option now behaves as documented again.
  :gl:`#4340`

- For inline-signing zones, if the unsigned version of the zone contains
  DNSSEC records, it was scheduled to be resigning. This unwanted behavior
  has been fixed. :gl:`#4350`

- Looking up stale data from the cache did not take into account local
  authoritative zones. This has been fixed. :gl:`#4355`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
