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

Notes for BIND 9.19.3
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

- In order to reduce unnecessary memory consumption in the cache,
  NXDOMAIN records are no longer retained past the normal negative
  cache TTL, even if ``stale-cache-enable`` is set to ``yes``.
  :gl:`#3386`.

Bug Fixes
~~~~~~~~~

- It was possible for a catalog zone consumer to process a catalog zone member
  zone when there was a configured pre-existing forward-only forward zone with
  the same name. This has been fixed. :gl:`#2506`.
