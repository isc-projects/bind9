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

Notes for BIND 9.16.46
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Parsing DNS messages with many different names could cause excessive
  CPU load. This has been fixed. :cve:`2023-4408`

  ISC would like to thank Shoham Danino from Reichman University, Anat
  Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv
  University, and Yuval Shavitt from Tel-Aviv University for bringing
  this vulnerability to our attention. :gl:`#4234`

- Specific queries could cause :iscman:`named` to crash with an
  assertion failure when ``nxdomain-redirect`` was enabled. This has
  been fixed. :cve:`2023-5517` :gl:`#4281`

- A bad interaction between DNS64 and serve-stale could cause
  :iscman:`named` to crash with an assertion failure, when both of these
  features were enabled. This has been fixed. :cve:`2023-5679`
  :gl:`#4334`

- Query patterns that continuously triggered cache database maintenance
  could cause an excessive amount of memory to be allocated, exceeding
  ``max-cache-size`` and potentially leading to all available memory on
  the host running :iscman:`named` being exhausted. This has been fixed.
  :cve:`2023-6516`

  ISC would like to thank Infoblox for bringing this vulnerability to
  our attention. :gl:`#4383`

Removed Features
~~~~~~~~~~~~~~~~

- The support for AES algorithm for DNS cookies has been deprecated.
  :gl:`#4421`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
