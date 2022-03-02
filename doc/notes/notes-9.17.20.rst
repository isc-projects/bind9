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

Notes for BIND 9.17.20
----------------------

New Features
~~~~~~~~~~~~

- New finer-grained ``update-policy`` rule types,
  ``krb5-subdomain-self-rhs`` and ``ms-subdomain-self-rhs``, were added.
  These rule types restrict updates to SRV and PTR records so that their
  content can only match the machine name embedded in the Kerberos
  principal making the change. :gl:`#481`

- Support for OpenSSL 3.0.0 APIs was added. :gl:`#2843`

Removed Features
~~~~~~~~~~~~~~~~

- OpenSSL 3.0.0 deprecated support for so-called "engines." Since BIND 9
  currently uses engine_pkcs11 for PKCS#11, compiling BIND 9 against an
  OpenSSL 3.0.0 build which does not retain support for deprecated APIs
  makes it impossible to use PKCS#11 in BIND 9. A replacement for
  engine_pkcs11 which employs the new "provider" approach introduced in
  OpenSSL 3.0.0 is in the making. :gl:`#2843`

- Since the old socket manager API has been removed, "socketmgr"
  statistics are no longer reported by the :ref:`statistics channel
  <statschannels>`. :gl:`#2926`

Feature Changes
~~~~~~~~~~~~~~~

- The default for ``dnssec-dnskey-kskonly`` was changed to ``yes``. This
  means that DNSKEY, CDNSKEY, and CDS RRsets are now only signed with
  the KSK by default. The additional signatures prepared using the ZSK
  when the option is set to ``no`` add to the DNS response payload
  without offering added value. :gl:`#1316`

- The default NSEC3 parameters for ``dnssec-policy`` were updated to no
  extra SHA-1 iterations and no salt (``NSEC3PARAM 1 0 0 -``).
  :gl:`#2956`

- Internal data structures maintained for each cache database are now
  grown incrementally when they need to be expanded. This helps maintain
  a steady response rate on a loaded resolver while these internal data
  structures are resized. :gl:`#2941`

- The output of :option:`rndc serve-stale status <rndc serve-stale>` has been clarified. It now
  explicitly reports whether retention of stale data in the cache is
  enabled (``stale-cache-enable``), and whether returning such data in
  responses is enabled (``stale-answer-enable``). :gl:`#2742`

- The `UseSTD3ASCIIRules`_ flag is now set for libidn2 function calls.
  This enables additional validation rules for IDN domains and hostnames
  in ``dig``. :gl:`#1610`

.. _UseSTD3ASCIIRules: http://www.unicode.org/reports/tr46/#UseSTD3ASCIIRules

Bug Fixes
~~~~~~~~~

- Reloading a catalog zone which referenced a missing/deleted member
  zone triggered a runtime check failure, causing ``named`` to exit
  prematurely. This has been fixed. :gl:`#2308`

- Some lame delegations could trigger a dependency loop, in which a
  resolver fetch waited for a name server address lookup which was
  waiting for the same resolver fetch. This could cause a recursive
  lookup to hang until timing out. This situation is now detected and
  prevented. :gl:`#2927`

- Log files using ``timestamp``-style suffixes were not always correctly
  removed when the number of files exceeded the limit set by
  ``versions``. This has been fixed. :gl:`#828`
