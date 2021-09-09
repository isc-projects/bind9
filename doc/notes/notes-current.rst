.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Add support for HTTPS and SVCB record types. :gl:`#1132`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- ``dnssec-signzone`` is now able to retain signatures from inactive
  predecessor keys without introducing additional signatures from the successor
  key. This allows for a gradual replacement of RRSIGs as they reach expiry.
  :gl:`#1551`

- The use of native PKCS#11 for Public-Key Cryptography in BIND 9 has been
  deprecated in favor of OpenSSL engine_pkcs11 from the OpenSC project.
  The ``--with-native-pkcs11`` configuration option will be removed from the
  next major BIND 9 release.  The option to use the engine_pkcs11 OpenSSL
  engine is already available in BIND 9; please see the ARM section on
  PKCS#11 for details. :gl:`#2691`

Bug Fixes
~~~~~~~~~

- When following QNAME minimization, BIND could use a stale zonecut from cache 
  to resolve the query, resulting in a non-minimized query. This has been
  fixed :gl:`#2665`

- Migrate a single key to CSK when reconfiguring a zone to make use of
  'dnssec-policy' :gl:`#2857`

- A recent change to the internal memory structure of zone databases
  inadvertently neglected to update the MAPAPI value for ``map``-format
  zone files. This caused ``named`` to attempt to load files into memory
  that were no longer compatible, triggering an assertion failure on
  startup. The MAPAPI value has now been updated, so ``named`` will
  reject outdated files when encountering them. :gl:`#2872`
