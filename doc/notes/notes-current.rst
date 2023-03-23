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

Notes for BIND 9.18.14
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

- Zone type ``delegation-only``, and the ``delegation-only`` and
  ``root-delegation-only`` options, have been deprecated; a warning will
  be logged when they are used.

  These options were created to address the SiteFinder controversy, in
  which certain top-level domains redirected misspelled queries to other
  sites instead of returning NXDOMAIN responses. Since top-level domains are
  now DNSSEC signed, and DNSSEC validation is active by default, the
  options are no longer needed. :gl:`#3953`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Previously, downloading large zones over TLS (XoT) from a primary
  could hang the transfer on the secondary, especially when the
  connection is unstable. This has been fixed. :gl:`#3867`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
