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

.. _relnotes_known_issues:

Known Issues
------------

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

- According to :rfc:`8310`, Section 8.1, the ``Subject`` field MUST NOT
  be inspected when verifying a remote certificate while establishing a
  DNS-over-TLS connection. Only ``subjectAltName`` must be checked
  instead. Unfortunately, some quite old versions of cryptographic
  libraries might lack the ability to ignore the ``Subject`` field. This
  should have minimal production-use consequences, as most of the
  production-ready certificates issued by certificate authorities will
  have ``subjectAltName`` set. In such cases, the ``Subject`` field is
  ignored. Only old platforms are affected by this, e.g. those supplied
  with OpenSSL versions older than 1.1.1. :gl:`#3163`

- Loading a large number of zones is significantly slower in BIND
  9.19.12 than in the previous development releases due to a new data
  structure being used for storing information about the zones to serve.
  This slowdown is considered to be a bug and will be addressed in a
  future BIND 9.19.x development release. :gl:`#4006`

- A flaw in reworked code responsible for accepting TCP connections may
  cause a visible performance drop for TCP queries on some platforms,
  notably FreeBSD.  This issue will be fixed in a future BIND 9.19.x
  development release. :gl:`#3985`
