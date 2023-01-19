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

Notes for BIND 9.19.10
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- The Differentiated Services Code Point (DSCP) feature has been removed:
  configuring DSCP values in ``named.conf``` is now a configuration error.
  :gl:`#3789`

- Specifying a ``port`` when configuring source addresses (i.e., as
  a parameter to ``query-source``, ``query-source-v6``,
  ``transfer-source``, ``transfer-source-v6``, ``notify-source``,
  ``notify-source-v6``, ``parental-source``, and
  ``parental-source-v6``, or in the ``source`` or ``source-v6``
  parameters to ``primaries``, ``parental-agents``, ``also-notify``,
  or ``catalog-zones``) has been deprecated.  In addition, the
  ``use-v4-udp-ports``, ``use-v6-udp-ports``, ``avoid-v4-udp-ports``,
  and ``avoid-v6-udp-ports`` options have also been deprecated.

  Warnings will be logged when any of these options are encountered
  in ``named.conf``.  In a future release, they will be made
  nonfunctional. :gl:`#3781`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- A constant stream of zone additions and deletions via ``rndc reconfig`` could
  cause increased memory consumption due to delayed cleaning of view memory.
  This has been fixed. :gl:`#3801`

- Improve the speed of the message digest algorithms (MD5, SHA-1,
  SHA-2) and NSEC3 hashing. :gl:`#3795`

- Setting :any:`parental-agents` to a resolver did not work because the RD bit
  was not set on DS requests. This has been fixed. :gl:`#3783`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
