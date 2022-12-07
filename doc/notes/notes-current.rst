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

Notes for BIND 9.16.36
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

- The option ``auto-dnssec`` is deprecated and will be removed in 9.19.
  Please migrate to ``dnssec-policy``. :gl:`#3667`

Bug Fixes
~~~~~~~~~

- None.

- The ``zone <name>/<class>: final reference detached`` log message was
  moved from the INFO log level to the DEBUG(1) log level to prevent the
  :iscman:`named-checkzone` tool from superfluously logging this message
  in non-debug mode. :gl:`#3707`

- When a catalog zone is removed from the configuration, in some
  cases a dangling pointer could cause a :iscman:`named` process
  crash. This has been fixed. :gl:`#3683`

- The ``named`` would wait for some outstanding recursing queries
  to finish before shutting down.  This has been fixed.  :gl:`#3183`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
