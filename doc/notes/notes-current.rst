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

Notes for BIND 9.16.49
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

- None.

Bug Fixes
~~~~~~~~~

- A regression in cache-cleaning code enabled memory use to grow
  significantly more quickly than before, until the configured
  ``max-cache-size`` limit was reached. This has been fixed. :gl:`#4596`

- Using :option:`rndc flush` inadvertently caused cache cleaning to
  become less effective. This could ultimately lead to the configured
  ``max-cache-size`` limit being exceeded and has now been fixed.
  :gl:`#4621`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
