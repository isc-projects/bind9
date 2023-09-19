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

Notes for BIND 9.19.18
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

- The new :any:`resolver-use-dns64` option enables ``named`` to apply
  :any:`dns64` rules to IPv4 server addresses when sending recursive
  queries, so that resolution can be performed over a NAT64 connection.
  :gl:`#608`

Removed Features
~~~~~~~~~~~~~~~~

- None.

- Configuring control channel to use Unix Domain Socket has an fatal error since
  BIND 9.18.  Completely remove the feature and make ``named-checkconf`` also
  report this as an error in the configuration. :gl:`#4311`

  The support for control channel over Unix Domain Sockets has been
  non-functional since BIND 9.18

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
