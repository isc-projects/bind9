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

Notes for BIND 9.16.42
----------------------

Security Fixes
~~~~~~~~~~~~~~

- The overmem cleaning process has been improved, to prevent the cache from
  significantly exceeding the configured ``max-cache-size`` limit.
  (CVE-2023-2828)

  ISC would like to thank Shoham Danino from Reichman University, Anat
  Bremler-Barr from Tel-Aviv University, Yehuda Afek from Tel-Aviv University,
  and Yuval Shavitt from Tel-Aviv University for bringing this vulnerability to
  our attention.  :gl:`#4055`

- A query that prioritizes stale data over lookup triggers a fetch to refresh
  the stale data in cache. If the fetch is aborted for exceeding the recursion
  quota, it was possible for :iscman:`named` to enter an infinite callback
  loop and crash due to stack overflow. This has been fixed. (CVE-2023-2911)
  :gl:`#4089`

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

- It could happen that after the ``stale-answer-client-timeout`` duration,
  a delegation from cache was returned to the client. This has now been fixed.
  :gl:`#3950`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
