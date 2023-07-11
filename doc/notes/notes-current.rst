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

Notes for BIND 9.19.16
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- The 'auto-dnssec' configuration option has now been removed. Please
  use :any:`dnssec-policy` or manual signing instead. The following options
  have become obsolete: :any:`dnskey-sig-validity`, :any:`dnssec-dnskey-kskonly`,
  :any:`dnssec-update-mode`, :any:`sig-validity-interval`, and
  :any:`update-check-ksk`. :gl:`#3672`.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- Return BADCOOKIE for out-of-date or otherwise bad, well formed
  DNS SERVER COOKIES.  Previously these were silently treated as
  DNS CLIENT COOKIES.  :gl:`#4194`

Bug Fixes
~~~~~~~~~

- None.

- Query-processing latency under load has been improved by reducing the
  uninterrupted time spent by resolving long cached chains of domain names.
  :gl:`#4185`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
