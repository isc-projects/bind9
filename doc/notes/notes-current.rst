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

Notes for BIND 9.18.10
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

- The option :any:`auto-dnssec` is deprecated and will be removed in 9.19.
  Please migrate to :any:`dnssec-policy`. :gl:`#3667`

- Deprecate setting the operating system limit (``coresize``, ``datasize``,
  ``files`` and ``stacksize``) from ``named.conf``.  These options should be set
  from the operating system (``ulimit``) or from the process supervisor
  (e.g. ``systemd``). :gl:`#3676`

Bug Fixes
~~~~~~~~~

- Increase the number of HTTP headers in the statistics channel from
  10 to 100 to accomodate for some browsers that send more that 10
  headers by default. :gl:`#3670`

- Copy TLS identifier when setting up primaries for catalog member
  zones. :gl:`#3638`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
