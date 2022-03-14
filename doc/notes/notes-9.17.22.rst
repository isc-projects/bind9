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

Notes for BIND 9.17.22
----------------------

New Features
~~~~~~~~~~~~

- :iscman:`named` now logs TLS pre-master secrets for debugging purposes when
  the ``SSLKEYLOGFILE`` environment variable is set. This enables
  troubleshooting issues with encrypted DNS traffic. :gl:`#2723`

Feature Changes
~~~~~~~~~~~~~~~

- Overall memory use by :iscman:`named` has been optimized and reduced,
  especially on systems with many CPU cores. :gl:`#2398` :gl:`#3048`

- :iscman:`named` formerly generated an ephemeral key and certificate for the
  ``tls ephemeral`` configuration using the RSA algorithm with 4096-bit
  keys. This has been changed to the ECDSA P-256 algorithm. :gl:`#2264`

Bug Fixes
~~~~~~~~~

- On FreeBSD, TCP connections leaked a small amount of heap memory,
  leading to an eventual out-of-memory problem. This has been fixed.
  :gl:`#3051`

- If signatures created by the ZSK were expired and the ZSK private key
  was offline, the signatures were not replaced. This behavior has been
  amended to replace the expired signatures with new signatures created
  using the KSK. :gl:`#3049`

- Under certain circumstances, the signed version of an inline-signed
  zone could be dumped to disk without the serial number of the unsigned
  version of the zone. This prevented resynchronization of the zone
  contents after :iscman:`named` restarted, if the unsigned zone file was
  modified while :iscman:`named` was not running. This has been fixed.
  :gl:`#3071`
