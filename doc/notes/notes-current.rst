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

- In order to reduce unnecessary memory consumption in the cache,
  NXDOMAIN records are no longer retained past the normal negative
  cache TTL, even if ``stale-cache-enable`` is set to ``yes``.
  :gl:`#3386`.

- The option :any:`auto-dnssec` is deprecated and will be removed in 9.19.
  Please migrate to :any:`dnssec-policy`. :gl:`#3667`

- Deprecate setting the operating system limit (``coresize``, ``datasize``,
  ``files`` and ``stacksize``) from ``named.conf``.  These options should be set
  from the operating system (``ulimit``) or from the process supervisor
  (e.g. ``systemd``). :gl:`#3676`

- Deprecate setting alternate local addresses for inbound zone transfers
  (:any:`alt-transfer-source`, :any:`alt-transfer-source-v6`,
  :any:`use-alt-transfer-source`). :gl:`#3694`

Bug Fixes
~~~~~~~~~

- Increase the number of HTTP headers in the statistics channel from
  10 to 100 to accomodate for some browsers that send more that 10
  headers by default. :gl:`#3670`


- Copy TLS identifier when setting up primaries for catalog member
  zones. :gl:`#3638`

- Fix an assertion failure in the statschannel caused by reading from the HTTP
  connection closed prematurely (connection error, shutdown). :gl:`#3693`

- The ``zone <name>/<class>: final reference detached`` log message was
  moved from the INFO log level to the DEBUG(1) log level to prevent the
  :iscman:`named-checkzone` tool from superfluously logging this message
  in non-debug mode. :gl:`#3707`

- When a catalog zone is removed from the configuration, in some
  cases a dangling pointer could cause a :iscman:`named` process
  crash. This has been fixed. :gl:`#3683`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
