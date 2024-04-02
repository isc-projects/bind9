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

New Features
~~~~~~~~~~~~

- Added RESOLVER.ARPA to the built in empty zones. :gl:`#4580`

Feature Changes
~~~~~~~~~~~~~~~

- Memory consumption of the new QP-trie database has been optimized and
  large zones now require roughly 15 % more memory than the old red-black tree
  data structure. :gl:`#4614`

- The ``sortlist`` option has been deprecated and will be removed
  in a future BIND 9.21.x release. Please don't rely on a specific
  order of resource records in the DNS messages.  :gl:`#4593`

- The ``fixed`` value for the ``rrset-order`` option and the corresponding
  ``./configure`` script option has been deprecated and will be removed in a
  future BIND 9.21.x release. Please don't rely on a specific order of resource
  records in the DNS messages.  :gl:`#4446`

Bug Fixes
~~~~~~~~~

- Some DNSSEC key rollovers were slowed down erroneously. This has been fixed.
  :gl:`#4552`

- Some ISO 8601 durations were accepted erroneously, leading to shorter
  durations than expected. This has been fixed. :gl:`#4624`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
