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

Notes for BIND 9.20.8
---------------------

New Features
~~~~~~~~~~~~

- Add support for EDE 20 (Not Authoritative)

  Support was added for EDE codes 20 (Not Authoritative) when client
  requests recursion (RD) but the server has recursion disabled.

  RFC 8914 mention EDE 20 should also be returned if the client doesn't
  have the RD bit set (and recursion is needed) but it doesn't apply for
  BIND as BIND would try to resolve from the "deepest" referral in
  AUTHORITY section. For example, if the client asks for "www.isc.org/A"
  but the server only knows the root domain, it will return NOERROR but
  no answer for "www.isc.og/A", just the list of other servers to ask.
  :gl:`#1836`

- Add support for EDE 7 and EDE 8.

  Support was added for EDE codes 7 (Signature Expired) and 8 (Signature
  Not Yet Valid) which might occur during DNSSEC validation. :gl:`#2715`

- Dig can now display the received BADVERS message during negotiation.

  Dig +showbadvers now displays the received BADVERS message and
  continues the EDNS version negotiation.  Previously to see the BADVERS
  message +noednsneg had to be specified which terminated the EDNS
  negotiation.  Additionally the specified EDNS value (+edns=value) is
  now used when making all the initial queries with +trace. i.e EDNS
  version negotiation will be performed with each server when performing
  the trace. :gl:`#5234`

- Add an rndc command to reset some statistics counters.

  The new ``reset-stats`` command for ``rndc`` allows some statistics
  counters to be reset during runtime. At the moment only two
  "high-water" counters are supported, so the ability to reset them
  after the initial peaks during the server's "warm-up" phase may be
  useful for some operators. :gl:`#5251`

Bug Fixes
~~~~~~~~~

- Restore NSEC3 closest encloser lookup improvements.

  A performance improvement for finding the closest encloser when
  generating authoritative responses from NSEC3 zones was previously
  reverted after a bug was found that could trigger an assertion
  failure. ( :gl:`#4460`, #4950, and #5108 for details.)  The bug has
  now been fixed, and the performance improvement has been restored.
  :gl:`#5204`

- Stop caching lack of EDNS support.

  `named` could falsely learn that a server doesn't support EDNS when a
  spoofed response was received; that subsequently prevented DNSSEC
  lookups from being made. This has been fixed. :gl:`#3949` :gl:`#5066`

- Fix resolver statistics counters for timed out responses.

  When query responses timed out, the resolver could incorrectly
  increase the regular responses counters, even if no response was
  received. This has been fixed. :gl:`#5193`

- Nested DNS validation could cause assertion failure.

  When multiple nested DNS validations were destroyed out of order, the
  EDE context could be freed before all EDE codes were copied, which
  could cause an assertion failure. This has been fixed. :gl:`#5213`

- [9.20] Wait for memory reclamation to finish in named-checkconf.

  Previously, when named-checkzone loaded the zone to the QP database,
  the delayed memory reclamation could cause an assertion check on exit.
  This has been fixed. :gl:`#5220`

- Ensure max-clients-per-query is at least clients-per-query.

  If the `max-clients-per-query` option is set to a lower value than
  `clients-per-query`, the value is adjusted to match
  `clients-per-query`. :gl:`#5224`

- Fix write after free in validator code.

  Raw integer pointers were being used for the validator's nvalidations
  and nfails values but the memory holding them could be freed before
  they ceased to be used.  Use reference counted counters instead.
  :gl:`#5239`

- Don't enforce NOAUTH/NOCONF flags in DNSKEYs.

  All DNSKEY keys are able to authenticate. The `DNS_KEYTYPE_NOAUTH`
  (and `DNS_KEYTYPE_NOCONF`) flags were defined for the KEY rdata type,
  and are not applicable to DNSKEY. Previously, however, because the
  DNSKEY implementation was built on top of KEY, the `_NOAUTH` flag
  prevented authentication in DNSKEYs as well. This has been corrected.
  :gl:`#5240`

- Fix several small DNSSEC timing issues.

  The following small issues related to `dnssec-policy` have been fixed:
  - In some cases the key manager inside BIND 9 could run every hour,
  while it could have run less often. - While `CDS` and `CDNSKEY`
  records will be removed correctly from the zone when the corresponding
  `DS` record needs to be updated, the expected timing metadata when
  this will happen was never set. - There were a couple of cases where
  the safety intervals are added inappropriately, delaying key rollovers
  longer than necessary. - If you have identical `keys` in your
  `dnssec-policy`, they may be retired inappropriately. Note that having
  keys with identical properties is discouraged in all cases.
  :gl:`#5242`


