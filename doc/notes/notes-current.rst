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

Notes for BIND 9.18.16
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

- The system test suite can now be executed with pytest (along with
  pytest-xdist for parallel execution). :gl:`#3978`

Removed Features
~~~~~~~~~~~~~~~~

- TKEY mode 2 (Diffie-Hellman Exchanged Keying) is now deprecated, and
  will be removed in a future release. A warning will be logged when
  the ``tkey-dhkey`` option is used in ``named.conf``. :gl:`#3905`

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- BIND could get stuck on reconfiguration when a `listen` statement
  for HTTP is removed from the configuration. That has been fixed.
  :gl:`#4071`

- It could happen that after the :any:`stale-answer-client-timeout` duration,
  a delegation from cache was returned to the client. This has now been fixed.
  :gl:`#3950`

- BIND could allocate too big buffers when sending data via
  stream-based DNS transports, leading to increased memory usage.
  This has been fixed. :gl:`#4038`

- When the :any:`stale-answer-enable` option was enabled and the
  :any:`stale-answer-client-timeout` option was enabled and larger than 0,
  ``named`` was taking two places from the :any:`clients-per-query` limit for
  each client and was failing to gradually auto-tune its value, as configured.
  This has been fixed. :gl:`#4074`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
