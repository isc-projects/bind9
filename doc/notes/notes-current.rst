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

Notes for BIND 9.19.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Validating DNS messages containing a lot of DNSSEC signatures could
  cause excessive CPU load, leading to a denial-of-service condition.
  This has been fixed. :cve:`2023-50387`

  ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel,
  and Michael Waidner from the German National Research Center for
  Applied Cybersecurity ATHENE. :gl:`#4424`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
