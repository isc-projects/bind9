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

- The ``lame-ttl`` option controls how long ``named`` caches certain
  types of broken responses from authoritative servers (see the
  `security advisory <https://kb.isc.org/docs/cve-2021-25219>`_ for
  details). This caching mechanism could be abused by an attacker to
  significantly degrade resolver performance. The vulnerability has been
  mitigated by changing the default value of ``lame-ttl`` to ``0`` and
  overriding any explicitly set value with ``0``, effectively disabling
  this mechanism altogether. ISC's testing has determined that doing
  that has a negligible impact on resolver performance while also
  preventing abuse. Administrators may observe more traffic towards
  servers issuing certain types of broken responses than in previous
  BIND 9 releases, depending on client query patterns. (CVE-2021-25219)

  ISC would like to thank Kishore Kumar Kothapalli of Infoblox for
  bringing this vulnerability to our attention. :gl:`#2899`

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

- The ``masterfile-format`` format ``map`` has been marked as deprecated and
  will be removed in a future release. :gl:`#2882`

- The statically compiled DLZ drivers have been marked as deprecated in favor of
  dynamically loaded DLZ modules and will be removed in a future major
  release. :gl:`#2814`

Bug Fixes
~~~~~~~~~

- When new IP addresses were added to the system during ``named``
  startup, ``named`` failed to listen on TCP for the newly added
  interfaces. :gl:`#2852`

- Reloading a catalog zone that referenced a missing/deleted zone
  caused a crash. This has been fixed. :gl:`#2308`
