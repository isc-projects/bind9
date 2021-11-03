.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.20
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Implement incremental resizing of RBT hash tables to perform the rehashing
  gradually instead all-at-once to be able to grow the memory usage gradually
  while keeping steady response rate during the rehashing. :gl:`#2941`

- Add finer-grained ``update-policy`` rule types, ``krb5-subdomain-self-rhs``
  and ``ms-subdomain-self-rhs``, that restrict updates to SRV and PTR records
  so that their content can only match the machine name embedded in the
  Kerberos principal making the change. :gl:`#481`

Removed Features
~~~~~~~~~~~~~~~~

- Add support for OpenSSL 3.0.0.  OpenSSL 3.0.0 deprecated 'engine' support.
  If OpenSSL 3.0.0 has been built without support for deprecated functionality
  pkcs11 via engine_pkcs11 is no longer available.  At this point in time
  there is no replacement ``provider`` for pkcs11 which is the replacement to
  the ``engine API``. :gl:`#2843`

Feature Changes
~~~~~~~~~~~~~~~

- Because the old socket manager API has been removed, "socketmgr"
  statistics are no longer reported by the
  :ref:`statistics channel <statschannels>`. :gl:`#2926`

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

- The default for ``dnssec-policy``'s ``nsec3param`` is changed to use
  no extra iterations and no salt. :gl:`#2956`.

Bug Fixes
~~~~~~~~~

- Reloading a catalog zone that referenced a missing/deleted zone
  caused a crash. This has been fixed. :gl:`#2308`

- Logfiles using ``timestamp``-style suffixes were not always correctly
  removed when the number of files exceeded the limit set by ``versions``.
  :gl:`#828`

- Some lame delegations could trigger a dependency loop, in which a
  resolver fetch was waiting for a name server address lookup which was
  waiting for the same resolver fetch. This could cause a recursive lookup
  to hang until timing out. This now detected and avoided. :gl:`#2927`
