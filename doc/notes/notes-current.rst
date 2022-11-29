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

Notes for BIND 9.19.8
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- Dynamic updates that add and remove DNSKEY and NSEC3PARAM records no
  longer trigger key rollovers and denial of existence operations. This
  also means that the option :any:`dnssec-secure-to-insecure` has been
  obsoleted. :gl:`#3686`

Feature Changes
~~~~~~~~~~~~~~~

- A ``configure`` option ``--with-tuning`` has been removed.  The compile-time
  settings that required different values based on "workload" have been either
  removed or a sensible default has been picked.  :gl:`#3664`

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

- Fix an assertion failure in the statschannel caused by reading from the HTTP
  connection closed prematurely (connection error, shutdown). :gl:`#3693`

- The ``zone <name>/<class>: final reference detached`` log message was
  moved from the INFO log level to the DEBUG(1) log level to prevent the
  :iscman:`named-checkzone` tool from superfluously logging this message
  in non-debug mode. :gl:`#3707`

- The new name compression code in BIND 9.19.7 was not compressing
  names in zone transfers that should have been compressed, so zone
  transfers were larger than before. :gl:`#3706`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
