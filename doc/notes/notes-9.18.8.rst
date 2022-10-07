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

Notes for BIND 9.18.8
---------------------

Known Issues
~~~~~~~~~~~~

- Upgrading from BIND 9.16.32, 9.18.6, or older, may require a manual
  configuration change. The following configurations are affected:

  - :any:`type primary` zones configured with :any:`dnssec-policy` but without
    either :any:`allow-update` or :any:`update-policy`
  - :any:`type secondary` zones configured with :any:`dnssec-policy`

  In these cases please add :namedconf:ref:`inline-signing yes;
  <inline-signing>` to individual zone configuration(s). Without applying this
  change :iscman:`named` will fail to start. For more details see
  https://kb.isc.org/docs/dnssec-policy-requires-dynamic-dns-or-inline-signing

- BIND 9.18 does not support dynamic updates forwarding (see
  :any:`allow-update-forwarding`) in conjuction with zone transfers
  over TLS (XoT). :gl:`#3512`

New Features
~~~~~~~~~~~~

- :iscman:`named` now logs the supported cryptographic algorithms during
  startup and in the output of :option:`named -V`. :gl:`#3541`

Feature Changes
~~~~~~~~~~~~~~~

- The ability to use pkcs11 via engine_pkcs11 has been restored, by only using
  deprecated APIs in OpenSSL 3.0.0. BIND needs to be compiled
  with '-DOPENSSL_API_COMPAT=10100' specified in the CFLAGS at
  compile time. :gl:`!6711`

- Add support for parsing and validating ``dohpath`` to SVBC records.
  :gl:`#3544`

Bug Fixes
~~~~~~~~~

- An assertion failure was fixed in ``named`` that was caused by aborting the statistics
  channel connection while sending statistics data to the client.  :gl:`#3542`

- Changing just the TSIG key names for primaries in catalog zones' member
  zones was not effective. :gl:`#3557`
