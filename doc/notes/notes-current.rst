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

Notes for BIND 9.19.22
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- The ``tls`` block was extended with a new ``cipher-suites`` option
  that allows setting allowed cipher suites for TLSv1.3. Please
  consult the documentation for additional details.
  :gl:`#3504`

- The statistics channel now includes counters that indicate the number
  of currently connected TCP IPv4/IPv6 clients. :gl:`#4425`

- The statistics channel's incoming zone transfers information now also shows
  the zones' "first refresh" flag, which indicates that a zone is not fully
  ready yet, and its first ever refresh is pending or is in-progress. The number
  of such zones is now also exposed by the ``rndc status`` command. :gl:`#4241`

- Add HSM support to :any:`dnssec-policy`. You can now configure keys with a
  ``key-store`` that allows you to set the directory to store the key files and
  set a PKCS#11 URI string. The latter requires OpenSSL 3 and a valid PKCS#11
  provider to be configured for OpenSSL. :gl`#1129`.

Removed Features
~~~~~~~~~~~~~~~~

- BIND 9 no longer supports non-zero :any:`stale-answer-client-timeout` values,
  when the feature is turned on. When using a non-zero value, ``named`` now
  generates a warning log message, and treats the value as ``0``. :gl:`#4447`

Feature Changes
~~~~~~~~~~~~~~~

- The ``dnssec-validation yes`` option now requires an explicitly configured
  :any:`trust-anchors` statement. If using manual trust anchors is not
  operationally required, then please consider using ``dnssec-validation auto``
  instead. :gl:`#4373`

- The red-black tree data structure used in the RBTDB (the default
  database implementation for cache and zone databases),
  has been replaced with QP-tries.  This is expected to improve
  performance and scalability, though in the current implementation
  it is known to have larger memory consumption.

  A side effect of this change is that zone files that are created with
  :any:`masterfile-style` ``relative`` - for example, the output of
  :any:`dnssec-signzone` - will no longer have multiple different
  `$ORIGIN` statements. There should be no other changes to server
  behavior.

  The old RBT-based database still exists for now, and can be used by
  specifying ``database rbt`` in a ``zone`` statement in ``named.conf``,
  or by compiling with ``configure --with-zonedb=rbt --with-cachedb=rbt``.
  :gl:`#4411`.

Bug Fixes
~~~~~~~~~

- Changes to ``listen-on`` statements were ignored on reconfiguration
  unless the port or interface address was changed, making it
  impossible to change a related listener transport type. That issue
  has been fixed.

  ISC would like to thank Thomas Amgarten for bringing this issue to
  our attention. :gl:`#4518`, :gl:`#4528`

- A use-after-free assertion might get triggered when the overmem cache
  cleaning triggers. :gl:`#4595`

  ISC would like to thank to Jinmei Tatuya from Infoblox for bringing
  this issue to our attention.

- A regression in cache-cleaning code enabled memory use to grow
  significantly more quickly than before, until the configured
  :any:`max-cache-size` limit was reached. This has been fixed.
  :gl:`#4596`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
