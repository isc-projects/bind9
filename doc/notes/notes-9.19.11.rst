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

Notes for BIND 9.19.11
----------------------

New Features
~~~~~~~~~~~~

- When using :any:`dnssec-policy`, you can now configure the digest type to
  use when ``CDS`` records need to be published with `cds-digest-types`. Also,
  with ``dnssec-signzone -G`` you can set which CDNSKEY/CDS records you want to
  publish. :gl:`#3837`

Removed Features
~~~~~~~~~~~~~~~~

- Support for Red Hat Enterprise Linux version 7 (and clones) has been dropped.
  A C11 compliant compiler (or better) is now required to compile BIND 9.
  :gl:`#3729`

- The functions that were in the ``libbind9`` shared library have been
  moved to the ``libisc`` and ``libisccfg`` libraries, and the
  now-empty ``libbind9`` has been removed and is no longer installed.

- The ``irs_resconf`` module has been moved to the ``libdns`` shared
  library and the now-empty ``libirs`` library has been removed and is
  no longer installed.

Feature Changes
~~~~~~~~~~~~~~~

- libuv support for receiving multiple UDP messages in a single system
  call (``recvmmsg()``) has been tweaked several times between libuv
  versions 1.35.0 and 1.40.0; the recommended libuv version is 1.40.0 or
  higher. New rules are now in effect for running with a different
  version of libuv than the one used at compilation time. These rules
  may trigger a fatal error at startup:

  - Building against or running with libuv versions 1.35.0 and 1.36.0 is
    now a fatal error.

  - Running with libuv version higher than 1.34.2 is now a fatal error
    when :iscman:`named` is built against libuv version 1.34.2 or lower.

  - Running with libuv version higher than 1.39.0 is now a fatal error
    when :iscman:`named` is built against libuv version 1.37.0, 1.38.0,
    1.38.1, or 1.39.0.

  This prevents the use of libuv versions that may trigger an assertion
  failure when receiving multiple UDP messages in a single system call.
  :gl:`#3840`

- Run catalog zone updates on the specialized "offload" threads to reduce the
  amount of time they block query processing on the main networking
  threads. This should increase the responsiveness of :iscman:`named`
  when catalog zone updates are being applied after a catalog zone has been
  successfully transferred. :gl:`#3881`

Bug Fixes
~~~~~~~~~

- :iscman:`named` could crash with an assertion failure when adding a new zone
  into the configuration file for a name, which is already configured as a
  member zone for a catalog zone. This has been fixed. :gl:`#3911`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
