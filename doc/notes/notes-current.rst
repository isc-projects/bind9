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

Notes for BIND 9.19.23
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Added RESOLVER.ARPA to the built in empty zones. :gl:`#4580`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- None.

- Some ISO 8601 durations were accepted erroneously, leading to shorter
  durations than expected. This has been fixed. :gl:`#4624`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
