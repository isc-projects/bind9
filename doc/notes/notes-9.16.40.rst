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

Notes for BIND 9.16.40
----------------------

Bug Fixes
~~~~~~~~~

- Logfiles using ``timestamp``-style suffixes were not always correctly
  removed when the number of files exceeded the limit set by ``versions``.
  :gl:`#828` :gl:`#3959`

- Performance of DNSSEC validation in zones with many DNSKEY records
  has been improved. :gl:`#3981`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
