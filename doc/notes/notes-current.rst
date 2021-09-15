.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.22
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The use of native PKCS#11 for Public-Key Cryptography in BIND 9 has been
  deprecated in favor of OpenSSL engine_pkcs11 from the OpenSC project.
  The ``--with-native-pkcs11`` configuration option will be removed from the
  next major BIND 9 release.  The option to use the engine_pkcs11 OpenSSL
  engine is already available in BIND 9; please see the ARM section on
  PKCS#11 for details. :gl:`#2691`

- ``named`` and ``named-checkconf`` now issue a warning when there is a single
  configured port in the ``query-source``, ``transfer-source``,
  ``notify-source``, and ``parental-source``, and/or in their respective IPv6 counterparts.
  :gl:`#2888`

- ``named`` and ``named-checkconf`` now return an error when the single configured
  port in the ``query-source``, ``transfer-source``, ``notify-source``,
  ``parental-source``, and/or their respective IPv6 counterparts clashes with the
  global listening port. This configuration is no longer supported as of BIND
  9.16.0 but no error was reported, although sending UDP messages
  (such as notifies) would fail. :gl:`#2888`

Bug Fixes
~~~~~~~~~

- When new IP addresses were added to the system during ``named``
  startup, ``named`` failed to listen on TCP for the newly added
  interfaces. :gl:`#2852`
