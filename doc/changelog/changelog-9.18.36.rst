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

BIND 9.18.36
------------

New Features
~~~~~~~~~~~~

- Implement -T cookiealwaysvalid. ``efbd698a2d``

  When `-T cookiealwaysvalid` is passed to `named`, DNS cookie checks
  for the incoming queries always pass, given they are structurally
  correct. :gl:`!10265`

Feature Changes
~~~~~~~~~~~~~~~

- Fix network manager issue when both success and timeout callbacks can
  be called for the same read request. ``d4cc98a175``

  This commit simplifies code flow in the tls_cycle_input() and makes
  the incoming data processing similar to that in TCP DNS. In
  particular, now we decipher all the the incoming data before making a
  single isc__nm_process_sock_buffer() call. Previously we would try to
  decipher data bit-by-bit before trying to process the deciphered bit
  via isc__nm_process_sock_buffer(). Doing like before made the code
  much less predictable, in particular in the areas like when reading is
  paused or resumed.

  The newer approach also allowed us to get rid of some old kludges.
  :gl:`#5247` :gl:`!10294`

Bug Fixes
~~~~~~~~~

- Add missing locks when returning addresses. ``ae573fd9dc``

  Add missing locks in dns_zone_getxfrsource4 et al.  Addresses CID
  468706, 468708, 468741, 468742, 468785, and 468778.

  Cleanup dns_zone_setxfrsource4 et al to now return void.

  Remove double copies with dns_zone_getprimaryaddr and
  dns_zone_getsourceaddr. :gl:`#4933` :gl:`!10260`

- Stop caching lack of EDNS support. ``84d0464646``

  `named` could falsely learn that a server doesn't support EDNS when a
  spoofed response was received; that subsequently prevented DNSSEC
  lookups from being made. This has been fixed. :gl:`#3949` :gl:`#5066`

- Fix resolver statistics counters for timed out responses.
  ``0e7419670e``

  When query responses timed out, the resolver could incorrectly
  increase the regular responses counters, even if no response was
  received. This has been fixed. :gl:`#5193` :gl:`!10288`

- Validating ADB fetches could cause a crash in import_rdataset()
  ``f24bacb190``

  Previously, in some cases, the resolver could return rdatasets of type
  CNAME or DNAME without the result code being set to `DNS_R_CNAME` or
  `DNS_R_DNAME`. This could trigger an assertion failure in the ADB. The
  resolver error has been fixed. :gl:`#5201` :gl:`!10330`

- Don't enforce NOAUTH/NOCONF flags in DNSKEYs. ``ddbea0b94b``

  All DNSKEY keys are able to authenticate. The `DNS_KEYTYPE_NOAUTH`
  (and `DNS_KEYTYPE_NOCONF`) flags were defined for the KEY rdata type,
  and are not applicable to DNSKEY. Previously, however, because the
  DNSKEY implementation was built on top of KEY, the `_NOAUTH` flag
  prevented authentication in DNSKEYs as well. This has been corrected.
  :gl:`#5240` :gl:`!10316`


