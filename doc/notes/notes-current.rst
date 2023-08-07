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

Notes for BIND 9.18.19
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Previously, sending a specially crafted message over the control
  channel could cause the packet-parsing code to run out of available
  stack memory, causing :iscman:`named` to terminate unexpectedly.
  This has been fixed. (CVE-2023-3341)

  ISC would like to thank Eric Sesterhenn from X41 D-Sec GmbH for
  bringing this vulnerability to our attention. :gl:`#4152`

- Previously, it was possible to remotely trigger a use-after-free error
  in the DNS-over-TLS transport code, specifically in the code
  responsible for sending data to the remote peer. This has been fixed.
  (CVE-2023-4236)

  ISC would like to thank Robert Story from USC/ISI Root Server
  Operations for bringing this vulnerability to our attention.
  :gl:`#4242`

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- The :any:`dnssec-must-be-secure` option has been deprecated and will be
  removed in a future release. :gl:`#4263`

Feature Changes
~~~~~~~~~~~~~~~

- None.

- Make :iscman:`nsupdate` honor the ``-v`` option. If set, and the server is
  specified, SOA queries are now send over TCP as well. :gl:`#1181`

Bug Fixes
~~~~~~~~~

- The value of If-Modified-Since header in statistics channel was not checked
  for length leading to possible buffer overflow by an authorized user.  We
  would like to emphasize that statistics channel must be properly setup to
  allow access only from authorized users of the system. :gl:`#4124`

  This issue was reported independently by Eric Sesterhenn of X41 D-SEC and
  Cameron Whitehead.

- The value of Content-Length header in statistics channel was not
  bound checked and negative or large enough value could lead to
  overflow and assertion failure.  :gl:`#4125`

  This issue was reported by Eric Sesterhenn of X41 D-SEC.

- Address memory leaks due to not clearing OpenSSL error stack. :gl:`#4159`

  This issue was reported by Eric Sesterhenn of X41 D-SEC.

- Following the introduction of krb5-subdomain-self-rhs and
  ms-subdomain-self-rhs update rules, removal of nonexistent PTR
  and SRV records via UPDATE could fail. This has been fixed. :gl:`#4280`

- The value of :any:`stale-refresh-time` was set to zero after ``rndc flush``.
  This has been fixed. :gl:`#4278`

- BIND could consume more memory than it needs. That has been fixed by
  using specialised jemalloc memory arenas dedicated to sending buffers. It
  allowed us to optimize the process of returning memory pages back to
  the operating system. :gl:`#4038`

- Prevent DNS message corruption on long DNS over TLS streams. :gl:`#4255`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
