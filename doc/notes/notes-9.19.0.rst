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

Notes for BIND 9.19.0
---------------------

Known Issues
~~~~~~~~~~~~

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

- See :ref:`above <relnotes_known_issues>` for a list of all known
  issues affecting this BIND 9 branch.

New Features
~~~~~~~~~~~~

- Add support for remote TLS certificate verification, both to
  :iscman:`named` and :iscman:`dig`, making it possible to implement
  Strict and Mutual TLS authentication, as described in :rfc:`9103`,
  Section 9.3. :gl:`#3163`

- :iscman:`dnssec-verify` and :iscman:`dnssec-signzone` now accept a
  ``-J`` option to specify a journal file to read when loading the zone
  to be verified or signed. :gl:`#2486`

Removed Features
~~~~~~~~~~~~~~~~

- The ``keep-response-order`` option has been declared obsolete and the
  functionality has been removed. :iscman:`named` expects DNS clients to
  be fully compliant with :rfc:`7766`. :gl:`#3140`

Feature Changes
~~~~~~~~~~~~~~~

- Run RPZ updates on the specialized "offload" threads to reduce the
  amount of time they block query processing on the main networking
  threads. This should increase the responsiveness of :iscman:`named`
  when RPZ updates are being applied after an RPZ zone has been
  successfully transferred. :gl:`#3190`

- The catalog zone implementation has been optimized to work with
  hundreds of thousands of member zones. :gl:`#3212` :gl:`#3744`
