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

Notes for BIND 9.18.36
----------------------

Feature Changes
~~~~~~~~~~~~~~~

- Make TLS data processing more reliable in various network conditions.

  BIND now deciphers incoming TLS data before processing it, making it
  more similar to the handling of TCP. This results in a more
  predictable behavior, particularly when reading from the stream is
  paused or resumed. Previously, this could result in an assertion
  failure when using XFR over TLS (XoT). This has been fixed.
  :gl:`#5247`

Bug Fixes
~~~~~~~~~

- Stop caching lack of EDNS support.

  :iscman:`named` could falsely learn that a server did not support EDNS
  when a spoofed response was received; that subsequently prevented
  DNSSEC lookups from being made.  This has been fixed. :gl:`#3949`
  :gl:`#5066`

- Fix resolver statistics counters for timed-out responses.

  When query responses timed out, the resolver could incorrectly
  increase the regular response counters, even if no response was
  received. This has been fixed. :gl:`#5193`

- Don't enforce NOAUTH/NOCONF flags in DNSKEYs.

  All DNSKEY keys are able to authenticate. The ``DNS_KEYTYPE_NOAUTH``
  (and ``DNS_KEYTYPE_NOCONF``) flags were defined for the KEY rdata
  type, and are not applicable to DNSKEY. Previously, however, because
  the DNSKEY implementation was built on top of KEY, the ``_NOAUTH``
  flag prevented authentication in DNSKEYs as well. This has been
  corrected. :gl:`#5240`

- Fix inconsistency in CNAME/DNAME handling during resolution.

  Previously, in some cases, the resolver could return rdatasets of type
  CNAME or DNAME without the result code being set to ``DNS_R_CNAME`` or
  ``DNS_R_DNAME``. This could trigger an assertion failure. This has
  been fixed. :gl:`#5201`
