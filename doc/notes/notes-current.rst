.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.18
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Support for HTTPS and SVCB record types has been added. :gl:`#1132`

Removed Features
~~~~~~~~~~~~~~~~

- Native PKCS#11 support has been removed; BIND 9 now uses OpenSSL engine_pkcs11 from the
  OpenSC project. :gl:`#2691`

Feature Changes
~~~~~~~~~~~~~~~

- When ``dnssec-signzone`` signs a zone using a successor key whose
  predecessor is still published, it now only refreshes signatures for
  RRsets which have an invalid signature, an expired signature, or a
  signature which expires within the provided cycle interval. This
  allows ``dnssec-signzone`` to gradually replace signatures in a zone
  whose ZSK is being rolled over (similarly to what ``auto-dnssec
  maintain;`` does). :gl:`#1551`

- ``dnssec-cds`` now only generates SHA-2 DS records by default and
  avoids copying deprecated SHA-1 records from a child zone to its
  delegation in the parent. If the child zone does not publish SHA-2 CDS
  records, ``dnssec-cds`` will generate them from the CDNSKEY records.
  The ``-a algorithm`` option now affects the process of generating DS
  digest records from both CDS and CDNSKEY records. Thanks to Tony
  Finch. :gl:`#2871`

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

- A recent change to the internal memory structure of zone databases
  inadvertently neglected to update the MAPAPI value for zone files in
  ``map`` format. This caused version 9.17.17 of ``named`` to attempt to
  load files into memory that were no longer compatible, triggering an
  assertion failure on startup. The MAPAPI value has now been updated,
  so ``named`` rejects outdated files when encountering them.
  :gl:`#2872`

- Stale data in the cache could cause ``named`` to send non-minimized
  queries despite QNAME minimization being enabled. This has been fixed.
  :gl:`#2665`

- When a DNSSEC-signed zone which only has a single signing key
  available is migrated to ``dnssec-policy``, that key is now treated as
  a Combined Signing Key (CSK). :gl:`#2857`

- When new IP addresses were added to the system during ``named``
  startup, ``named`` failed to listen on TCP for the newly added
  interfaces. :gl:`#2852`
