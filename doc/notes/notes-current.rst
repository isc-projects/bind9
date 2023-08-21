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

Notes for BIND 9.19.17
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

- The value of If-Modified-Since header in statistics channel was not checked
  for length leading to possible buffer overflow by an authorized user.  We
  would like to emphasize that statistics channel must be properly setup to
  allow access only from authorized users of the system. :gl:`#4124`

  This issue was reported independently by Eric Sesterhenn of X41 D-SEC and
  Cameron Whitehead.

- The value of Content-Length header in statistics channel was not bound checked
  and negative or large enough value could lead to overflow and assertion failure.
  :gl:`#4125`

  This issue was reported by Eric Sesterhenn of X41 D-SEC.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
