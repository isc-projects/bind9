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

- Ability to specify supported TLS protocol versions within ``tls``
  clauses (e.g. ``protocols { TLSv1.2; TLSv1.3; };``). :gl:`#2795`

- New options within ``tls`` clauses were implemented, namely:
  - ``dhparam-file "<path_to_file>";`` to specify Diffie-Hellman parameters;
  - ``ciphers "<cipher_list>";`` to specify OpenSSL ciphers list;
  - ``prefer-server-ciphers yes|no;`` to assert server or client ciphers preference;
  - ``session-tickets yes|no;`` to explicitly enable or disable stateless TLS session tickets (see RFC5077).
  These options allow finer control over TLS protocol features and make it
  possible to achieve perfect forward secrecy for DNS-over-TLS and
  DNS-over-HTTPS. :gl:`#2796`

Removed Features
~~~~~~~~~~~~~~~~

- Native PKCS#11 support has been removed; BIND 9 now uses OpenSSL engine_pkcs11 from the
  OpenSC project. :gl:`#2691`

- The ``masterfile-format`` format ``map`` has removed.  If you are using the
  ``map`` format, you are advised to convert the zones to ``raw`` format with
  ``named-compilezone`` and change the configuration prior to BIND 9
  upgrade. :gl:`#2882`

- Remove old-style DLZ drivers that had to be enabled in ``named`` during the
  compile time.  The new-style dynamically loaded DLZ modules should be used
  as a replacement. :gl:`#2814`

Feature Changes
~~~~~~~~~~~~~~~

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

- Under specific circumstances, zone transfers over TCP and TLS could be
  interrupted prematurely. This has been fixed. :gl:`#2917`

- Reloading a catalog zone that referenced a missing/deleted zone
  caused a crash. This has been fixed. :gl:`#2308`
