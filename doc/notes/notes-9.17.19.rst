.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.19
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

New Features
~~~~~~~~~~~~

- It is now possible to specify the TLS protocol versions to support for
  each ``tls`` configuration clause (e.g. ``protocols { TLSv1.2;
  TLSv1.3; };``). :gl:`#2795`

- New options for ``tls`` configuration clauses were implemented,
  namely:

  - ``dhparam-file "<path_to_file>";`` for specifying Diffie-Hellman
    parameters,

  - ``ciphers "<cipher_list>";`` for specifying OpenSSL ciphers to use,

  - ``prefer-server-ciphers <yes|no>;`` for specifying whether server
    ciphers or client ciphers should be preferred (this controls
    OpenSSL's ``SSL_OP_CIPHER_SERVER_PREFERENCE`` option),

  - ``session-tickets <yes|no>;`` for enabling/disabling stateless TLS
    session tickets (see :rfc:`5077`).

  These options allow finer control over TLS protocol configuration and
  make achieving perfect forward secrecy (PFS) possible for DNS-over-TLS
  (DoT) and DNS-over-HTTPS (DoH). :gl:`#2796`

Removed Features
~~~~~~~~~~~~~~~~

- Native PKCS#11 support has been removed; BIND 9 now :ref:`uses
  engine_pkcs11 for PKCS#11<pkcs11>`. engine_pkcs11 is an OpenSSL engine
  which is part of the `OpenSC`_ project. :gl:`#2691`

- Old-style Dynamically Loadable Zones (DLZ) drivers that had to be
  enabled in ``named`` at build time have been removed. New-style DLZ
  modules should be used as a replacement. :gl:`#2814`

- Support for the ``map`` zone file format (``masterfile-format map;``)
  has been removed. Users relying on the ``map`` format are advised to
  convert their zones to the ``raw`` format with ``named-compilezone``
  and change the configuration appropriately prior to upgrading BIND 9.
  :gl:`#2882`

.. _OpenSC: https://github.com/OpenSC/libp11

Feature Changes
~~~~~~~~~~~~~~~

- The network manager API is now used for sending all outgoing DNS
  queries and requests from ``named`` and related tools, including
  ``delv``, ``mdig``, and ``nsupdate``. :gl:`#2401`

- ``named`` and ``named-checkconf`` now exit with an error when a single
  port configured for ``query-source``, ``transfer-source``,
  ``notify-source``, ``parental-source``, and/or their respective IPv6
  counterparts clashes with a global listening port. This configuration
  has not been supported since BIND 9.16.0, but no error was reported
  until now (even though sending UDP messages such as NOTIFY failed).
  :gl:`#2888`

- ``named`` and ``named-checkconf`` now issue a warning when there is a
  single port configured for ``query-source``, ``transfer-source``,
  ``notify-source``, ``parental-source``, and/or for their respective
  IPv6 counterparts. :gl:`#2888`

- Zone transfers over TLS (XoT) now need the ``dot`` Application-Layer
  Protocol Negotiation (ALPN) token to be selected in the TLS handshake,
  as required by :rfc:`9103` section 7.1. :gl:`#2794`

Bug Fixes
~~~~~~~~~

- A recent change introduced in BIND 9.17.18 inadvertently broke
  backward compatibility for the ``check-names master ...`` and
  ``check-names slave ...`` options, causing them to be silently
  ignored. This has been fixed and these options now work properly
  again. :gl:`#2911`

- When new IP addresses were set up by the operating system during
  ``named`` startup, it could fail to listen for TCP connections on the
  newly added interfaces. :gl:`#2852`

- Under specific circumstances, zone transfers over TCP and TLS could be
  interrupted prematurely. This has been fixed. :gl:`#2917`
