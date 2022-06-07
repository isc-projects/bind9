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

Notes for BIND 9.19.5
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Zones using ``dnssec-policy`` now require dynamic DNS or
  ``inline-signing`` to be configured explicitly :gl:`#3381`.

Bug Fixes
~~~~~~~~~

- Fix a serve-stale bug, where BIND would try to return stale data from cache
  for lookups that received duplicate queries or queries that would be dropped.
  This bug resulted in premature SERVFAIL responses, and has now been resolved.
  :gl:`#2982`
