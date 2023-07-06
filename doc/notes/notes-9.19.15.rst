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

Notes for BIND 9.19.15
----------------------

Feature Changes
~~~~~~~~~~~~~~~

- The ``relaxed`` QNAME minimization mode now uses NS records. This
  reduces the number of queries :iscman:`named` makes when resolving, as
  it allows the non-existence of NS RRsets at non-referral nodes to be
  cached in addition to the normally cached referrals. :gl:`#3325`

Bug Fixes
~~~~~~~~~

- The ability to read HMAC-MD5 key files, which was accidentally lost in
  BIND 9.19.6 and BIND 9.18.8, has been restored. :gl:`#3668`
  :gl:`#4154`

- Several minor stability issues with the catalog zone implementation
  have been fixed. :gl:`#4132` :gl:`#4136` :gl:`#4171`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
