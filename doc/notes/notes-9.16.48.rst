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

Notes for BIND 9.16.48
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Validating DNS messages containing a lot of DNSSEC signatures could
  cause excessive CPU load, leading to a denial-of-service condition.
  This has been fixed. :cve:`2023-50387`

  ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel,
  and Michael Waidner from the German National Research Center for
  Applied Cybersecurity ATHENE for bringing this vulnerability to our
  attention. :gl:`#4424`

- Preparing an NSEC3 closest encloser proof could cause excessive CPU
  load, leading to a denial-of-service condition. This has been fixed.
  :cve:`2023-50868` :gl:`#4459`

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

- Support for using AES as the DNS COOKIE algorithm (``cookie-algorithm
  aes;``) has been deprecated and will be removed in a future release.
  Please use the current default, SipHash-2-4, instead. :gl:`#4421`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
