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

Notes for BIND 9.19.6
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

- A new configuration option ``require-cookie`` has been introduced, it
  specifies if there should be a DNS COOKIE in the response for a given
  prefix and if not named falls back to TCP.  This is useful if you know
  a given server support DNS COOKIE.  It can also be used to force all
  non DNS COOKIE responses to fall back to TCP.  :gl:`#2295`

- Add libsystemd sd_notify() integration that allows the ``named`` to report
  status to the supervisor.  This allows the systemd to wait until ``named`` is
  fully started before starting other services that depend on name resolution.
  :gl:`#1176`

- The ``nsupdate`` tool now supports DNS-over-TLS (DoT). :gl:`#1781`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- When an international domain name is not valid according to IDNA2008,
  :program:`dig` will now try to convert it according to IDNA2003 rules,
  or pass it through unchanged, instead of stopping with an error message.
  You can use the ``idna2`` utility for checking IDNA syntax. :gl:`#3485`.

- The DNSSEC signing data included in zone statistics identified
  keys only by the key ID; this caused confusion when two keys using
  different algorithms had the same ID. Zone statistics now identify
  keys using the algorithm number, followed by "+", followed by the
  key ID: for example, "8+54274". :gl:`#3525`

- The ability to use pkcs11 via engine_pkcs11 has been restored, by only using
  deprecated APIs in OpenSSL 3.0.0. BIND needs to be compiled
  with '-DOPENSSL_API_COMPAT=10100' specified in the CFLAGS at
  compile time. :gl:`!6711`

Bug Fixes
~~~~~~~~~

- An assertion failure was fixed in ``named`` that was caused by aborting the statistics
  channel connection while sending statistics data to the client.  :gl:`#3542`

- :iscman:`named` could incorrectly return non-truncated, glueless
  referrals for responses whose size was close to the UDP packet size
  limit. :gl:`#1967`
