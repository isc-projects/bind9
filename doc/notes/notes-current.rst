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

- Implement incremental resizing of RBT hash tables to perform the rehashing
  gradually instead all-at-once to be able to grow the memory usage gradually
  while keeping steady response rate during the rehashing. :gl:`#2941`

- Add finer-grained ``update-policy`` rule types, ``krb5-subdomain-self-rhs``
  and ``ms-subdomain-self-rhs``, that restrict updates to SRV and PTR records
  so that their content can only match the machine name embedded in the
  Kerberos principal making the change. :gl:`#481`

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

- The network manager API is now used by ``named`` and related tools,
  including ``nsupdate``, ``delv``, ``mdig``, to send all outgoing DNS
  queries and requests. :gl:`#2401`

- Because the old socket manager API has been removed, "socketmgr"
  statistics are no longer reported by the statistics channel. :gl:`#2926`

- Zone transfers over TLS (XoT) now need "dot" Application-Layer Protocol
  Negotiation (ALPN) tag to be negotiated, as required by the RFC 9103. :gl: `#2794`

- `UseSTD3ASCIIRules`_ is now enabled for IDN support. This enables additional
  validation rules for domains and hostnames within dig.  :gl:`#1610`

.. _UseSTD3ASCIIRules: http://www.unicode.org/reports/tr46/#UseSTD3ASCIIRules

- The default for ``dnssec-dnskey-kskonly`` is changed to ``yes``. This means
  that DNSKEY, CDNSKEY, and CDS RRsets are now only signed with the KSK by
  default. The additional signatures from the ZSK that are added if the option
  is set to ``no`` add to the DNS response payload without offering added value.
  :gl:`#1316`

- The output of ``rndc serve-stale status`` has been clarified. It now
  explicitly reports whether retention of stale data in the cache is enabled
  (``stale-cache-enable``), and whether returning of such data in responses is 
  enabled (``stale-answer-enable``). :gl:`#2742`

Bug Fixes
~~~~~~~~~

- When new IP addresses were added to the system during ``named``
  startup, ``named`` failed to listen on TCP for the newly added
  interfaces. :gl:`#2852`

- Under specific circumstances, zone transfers over TCP and TLS could be
  interrupted prematurely. This has been fixed. :gl:`#2917`

- Reloading a catalog zone that referenced a missing/deleted zone
  caused a crash. This has been fixed. :gl:`#2308`

- Logfiles using ``timestamp``-style suffixes were not always correctly
  removed when the number of files exceeded the limit set by ``versions``.
  :gl:`#828`

- Some lame delegations could trigger a dependency loop, in which a
  resolver fetch was waiting for a name server address lookup which was
  waiting for the same resolver fetch. This could cause a recursive lookup
  to hang until timing out. This now detected and avoided. :gl:`#2927`
