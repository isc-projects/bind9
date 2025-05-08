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

Notes for BIND 9.21.8
---------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-40775] Prevent assertion when processing TSIG algorithm.

  DNS messages that included a Transaction Signature (TSIG) containing
  an invalid value in the algorithm field caused :iscman:`named` to
  crash with an assertion failure. This has been fixed.
  :cve:`2025-40775` :gl:`#5300`

New Features
~~~~~~~~~~~~

- Implement tcp-primaries-timeout.

  The new `tcp-primaries-timeout` configuration option works the same
  way as the older `tcp-initial-timeout` option, but applies only to the
  TCP connections made to the primary servers, so that the timeout value
  can be set separately for them. By default, it's set to 150, which is
  15 seconds. :gl:`#3649`

Feature Changes
~~~~~~~~~~~~~~~

- Use jinja2 templates in system tests.

  `python-jinja2` is now required to run system tests. :gl:`#4938`

Bug Fixes
~~~~~~~~~

- Fix EDNS yaml output.

  `dig` was producing invalid YAML when displaying some EDNS options.
  This has been corrected.

  Several other improvements have been made to the display of EDNS
  option data: - We now use the correct name for the UPDATE-LEASE
  option, which was previously displayed as "UL", and split it into
  separate LEASE and LEASE-KEY components in YAML mode. - Human-readable
  durations are now displayed as comments in YAML mode so as not to
  interfere with machine parsing. - KEY-TAG options are now displayed as
  an array of integers in YAML mode. - EDNS COOKIE options are displayed
  as separate CLIENT and SERVER components, and cookie STATUS is a
  retrievable variable in YAML mode. :gl:`#5014`

- Return DNS COOKIE and NSID with BADVERS.

  This change allows the client to identify the server that returns the
  BADVERS and to provide a DNS SERVER COOKIE to be included in the
  resend of the request. :gl:`#5235`

- Disable own memory context for libxml2 on macOS.

  Apple broke custom memory allocation functions in the system-wide
  libxml2 starting with macOS Sequoia 15.4.  Usage of the custom memory
  allocation functions has been disabled on macOS. :gl:`#5268`

- `check_private` failed to account for the length byte before the OID.

  In PRIVATEOID keys, the key data begins with a length byte followed
  by an ASN.1 object identifier that indicates the cryptographic
  algorithm  to use. Previously, the length byte was not accounted for
  when  checking the contents of keys and signatures, which could have
  led to interoperability problems with any zones signed using
  PRIVATEOID. This has been fixed. :gl:`#5270`

- Fix a serve-stale issue with a delegated zone.

  When ``stale-answer-client-timeout 0`` option was enabled, it could be
  ignored when resolving a zone which is a delegation of an
  authoritative zone belonging to the resolver. This has been fixed.
  :gl:`#5275`

- Return the correct NSEC3 records for NXDOMAIN responses.

  The wrong NSEC3 records were sometimes returned as proof that the
  QNAME did not exist. This has been fixed. :gl:`#5292`


