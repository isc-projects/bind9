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

Notes for BIND 9.18.17
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- If a response from an authoritative server has its RCODE set to
  FORMERR and contains an echoed EDNS COOKIE option that was present in
  the query, :iscman:`named` now retries sending the query to the
  same server without an EDNS COOKIE option. :gl:`#4049`

- Use NS records for relaxed QNAME-minimization mode.  This reduces the
  number of queries ``named`` makes when resolving, as it allows the
  non-existence of NS RRsets at non-referral nodes to be cached in
  addition to the normally cached referrals. :gl:`#3325`

Bug Fixes
~~~~~~~~~

- Restored the abilty to read HMAC-MD5 K file pairs (K*.+157+*.{key,private})
  that was accidentally lost. :gl:`#4154`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
