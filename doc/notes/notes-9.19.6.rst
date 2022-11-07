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

Known Issues
~~~~~~~~~~~~

- Upgrading from BIND 9.16.32, 9.18.6, 9.19.4, or any older version may
  require a manual configuration change. The following configurations
  are affected:

  - :any:`type primary` zones configured with :any:`dnssec-policy` but
    without either :any:`allow-update` or :any:`update-policy`,
  - :any:`type secondary` zones configured with :any:`dnssec-policy`.

  In these cases please add :namedconf:ref:`inline-signing yes;
  <inline-signing>` to the individual zone configuration(s). Without
  applying this change, :iscman:`named` will fail to start. For more
  details, see
  https://kb.isc.org/docs/dnssec-policy-requires-dynamic-dns-or-inline-signing

- See :ref:`above <relnotes_known_issues>` for a list of all known
  issues affecting this BIND 9 branch.

New Features
~~~~~~~~~~~~

- Support for parsing and validating the ``dohpath`` service parameter
  in SVCB records was added. :gl:`#3544`

- :iscman:`named` now supports forwarding Dynamic DNS updates through
  DNS-over-TLS (DoT). :gl:`#3512`

- The :iscman:`nsupdate` tool now supports DNS-over-TLS (DoT).
  :gl:`#1781`

- :iscman:`named` now logs the supported cryptographic algorithms during
  startup and in the output of :option:`named -V`. :gl:`#3541`

- A new configuration option :any:`require-cookie` has been introduced.
  It specifies whether there should be a DNS COOKIE in the response for
  a given prefix; if not, :iscman:`named` falls back to TCP. This is
  useful if it is known that a given server supports DNS COOKIE. It can
  also be used to force all non-DNS COOKIE responses to fall back to
  TCP. :gl:`#2295`

- Support for libsystemd's ``sd_notify()`` function was added, enabling
  :iscman:`named` to report its status to the init system. This allows
  systemd to wait until :iscman:`named` is fully ready before starting
  other services that depend on name resolution. :gl:`#1176`

- The ``recursion not available`` and ``query (cache) '...' denied`` log
  messages were extended to include the name of the ACL that caused a
  given query to be denied. :gl:`#3587`

Feature Changes
~~~~~~~~~~~~~~~

- When an international domain name is not valid according to IDNA2008,
  :iscman:`dig` now tries to convert it according to IDNA2003 rules, or
  pass it through unchanged, instead of stopping with an error message.
  The ``idna2`` utility can be used to check IDNA syntax. :gl:`#3527`

- The DNSSEC signing data included in zone statistics identified
  keys only by the key ID; this caused confusion when two keys using
  different algorithms had the same ID. Zone statistics now identify
  keys using the algorithm number, followed by "+", followed by the
  key ID: for example, ``8+54274``. :gl:`#3525`

- The ability to use PKCS#11 via engine_pkcs11 has been restored, by
  using only deprecated APIs in OpenSSL 3.0.0. BIND 9 needs to be
  compiled with ``-DOPENSSL_API_COMPAT=10100`` specified in the CFLAGS
  environment variable at compile time. :gl:`#3578`

- Compiling BIND 9 now requires at least libuv version 1.34.0 or higher.
  libuv should be available on all supported platforms either as a
  native package or as a backport. :gl:`#3567`

Bug Fixes
~~~~~~~~~

- An assertion failure was fixed in :iscman:`named` that was caused by
  aborting the statistics channel connection while sending statistics
  data to the client. :gl:`#3542`

- :iscman:`named` could incorrectly return non-truncated, glueless
  referrals for responses whose size was close to the UDP packet size
  limit. This has been fixed. :gl:`#1967`

- Changing just the TSIG key names for primaries in catalog zones'
  member zones was not effective. This has been fixed. :gl:`#3557`
