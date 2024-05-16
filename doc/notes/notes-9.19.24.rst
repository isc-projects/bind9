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

Notes for BIND 9.19.24
----------------------

New Features
~~~~~~~~~~~~

- A new option :any:`signatures-jitter` has been added to :any:`dnssec-policy`
  to allow signature expirations to be spread out over a period of time.
  :gl:`#4554`

- A new DNSSEC tool :iscman:`dnssec-ksr` has been added to create Key Signing
  Request (KSR) and Signed Key Response (SKR) files. :gl:`#1128`

- Queries and responses now emit distinct dnstap entries for DNS-over-TLS (DoT)
  and DNS-over-HTTPS (DoH), and :any:`dnstap-read` understands these entries.
  :gl:`#4523`

Removed Features
~~~~~~~~~~~~~~~~

- The :iscman:`named` command-line option :option:`-U <named -U>`, which
  specified the number of UDP dispatches, has been removed. Using it now
  returns a warning. :gl:`#1879`

Feature Changes
~~~~~~~~~~~~~~~

- Querying the statistics channel no longer blocks DNS communication on the
  networking event loop level. :gl:`#4680`

- DNSSEC signatures that are not valid because the current time falls outside
  the signature inception and expiration dates no longer count towards maximum
  validation and maximum validation failure limits. :gl:`#4586`

- Multiple RNDC messages are now processed when sent in a single TCP message.

  ISC would like to thank Dominik Thalhammer for reporting the issue and
  preparing the initial patch. :gl:`#4416`

- :iscman:`dnssec-keygen` now allows the options :option:`-k <dnssec-keygen
  -k>` and :option:`-f <dnssec-keygen -f>` to be used together. This allows the
  creation of keys for a given :any:`dnssec-policy` that match only the KSK
  (``-fK``) or ZSK (``-fZ``) roles. :gl:`#1128`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
