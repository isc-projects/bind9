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

Notes for BIND 9.18.18
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

- Processing already queued queries received over TCP can cause assertion
  failure when the server is reconfigured at the same time or the cache has been
  flushed.  This has been fixed to not process queued already received queries
  over TCP while the server is in the "exclusive" mode.  :gl:`#4200`

- Ignore :any:`max-zone-ttl` for :any:`dnssec-policy` "insecure",
  otherwise some zones will not be loaded if they use a TTL value larger
  than 86400. :gl:`#4032`.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
