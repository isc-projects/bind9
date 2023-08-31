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

Notes for BIND 9.16.44
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Previously, sending a specially crafted message over the control
  channel could cause the packet-parsing code to run out of available
  stack memory, causing :iscman:`named` to terminate unexpectedly.
  This has been fixed. :cve:`2023-3341`

  ISC would like to thank Eric Sesterhenn from X41 D-Sec GmbH for
  bringing this vulnerability to our attention. :gl:`#4152`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
