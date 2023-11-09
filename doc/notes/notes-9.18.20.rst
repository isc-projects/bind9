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

Notes for BIND 9.18.20
----------------------

Feature Changes
~~~~~~~~~~~~~~~

- B.ROOT-SERVERS.NET addresses are now 170.247.170.2 and 2801:1b8:10::b.
  :gl:`#4101`

Bug Fixes
~~~~~~~~~

- For inline-signing zones, if the unsigned version of the zone contains
  DNSSEC records, it was scheduled to be resigning. This unwanted behavior
  has been fixed. :gl:`#4350`

- The :any:`lock-file` file was being removed when it shouldn't
  have been making it ineffective if named was started 3 or more
  times. :gl:`#4387`

- When :any:`lock-file` was used at the same time as :option:`named -X`, the
  assertion failure would be triggered.  This has been fixed. :gl:`#4386`

- Looking up stale data from the cache did not take into account local
  authoritative zones. This has been fixed. :gl:`#4355`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
