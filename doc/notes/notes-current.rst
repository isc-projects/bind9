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

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- A new option :any:`signatures-jitter` is added to :any:`dnssec-policy` to
  spread out signature expiration times over a period of time. :gl:`#4554`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Querying the statistics channel no longer blocks the DNS communication
  on the networking event loop. :gl:`#4680`

- DNSSEC signatures that are not valid because the current time falls outside
  the signature inception and expiration dates no longer count towards maximum
  validation and maximum validation failures limits. :gl:`#4586`

- Multiple RNDC messages will be processed when sent in a single TCP
  message.

  ISC would like to thank Dominik Thalhammer for reporting the issue
  and preparing the initial patch. :gl:`#4416`

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
