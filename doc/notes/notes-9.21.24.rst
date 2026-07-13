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

Notes for BIND 9.21.24
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-11331] Fix handling of rpz CNAME expansion that returns name
  too long.

  Previously, if the expansion of a wildcard CNAME RPZ policy resulted
  in a name that exceeded the length limit, a self referential CNAME and
  the original address record were returned, allowing the policy to be
  bypassed.  In branches up to 9.20, this also left query processing in
  an inconsistent state which could trigger an assertion failure.  We
  now return a YXDOMAIN response, without the address.

  ISC would like to thank Laith Mash'al (0xmshal) for bringing this
  issue to our attention. :gl:`#5856`

- [CVE-2026-11721] Invalid signed wildcard records were being accepted.

  Signed wildcard responses in which the Labels field in the `RRSIG`
  record was less than the number of labels in the Signer Name field
  were being incorrectly accepted. This in turn broke
  `synth-from-dnssec`, which depends on such records being correctly
  validated. This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for bringing this issue
  to our attention. :gl:`#5871`

- [CVE-2026-13321] Fix DNSSEC validation bypass via out-of-zone NSEC
  Next Field.

  A malicious zone with out-of-zone NSEC next owner names can cause a
  DNSSEC validating resolver to cache such record and, if
  `synth-from-dnssec` is enabled, to generate negative answers for any
  zone that is covered by the range.

  ISC would like to thank Qifan Zhang of Palo Alto Networks for
  reporting the issue. :gl:`#5873`

- [CVE-2026-10723] Correct verification of NSEC3 signer name.

  BIND 9 accepted child-zone NSEC3 records where the first label equals
  the hash of the parent zone as valid parent-zone closest encloser
  proofs. This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5874`

- [CVE-2026-10822] Malformed DNSKEY records could trigger an assertion.

  Previously, `dns_name_fromwire()` did not honor the record boundary
  when reading names from the wire, allowing malformed records to be
  accepted when they should not have been. In particular, malformed
  DNSKEY records could trigger an assertion failure when being printed.
  This has been fixed. :gl:`#6004`

- Reclaim memory promptly when DNSSEC validations are canceled.

  When a resolver is flooded with queries that require DNSSEC validation
  — for example during a random-subdomain attack — many of those
  validations are canceled before they complete. Previously a canceled
  validation still kept its place in the internal work queue and held
  the associated response in memory until that queued work eventually
  ran, so memory could climb sharply under sustained load. The canceled
  work is now dropped as soon as the validation is canceled, releasing
  the memory it was holding.

- [CVE-2026-11605] Prevent excessive validation work from crafted
  negative responses.

  A validating resolver could be made to perform a large amount of
  DNSSEC validation work in response to a single answer, consuming
  excessive CPU. A malicious authoritative server triggers this by
  returning a signed negative answer (NXDOMAIN or NODATA) padded with
  many denial-of-existence proof records, which the resolver continued
  to verify beyond its per-query validation limit. It now enforces that
  limit on negative answers and returns SERVFAIL once the limit is
  reached.

  Closes: https://gitlab.isc.org/isc-projects/bind9/-/work_items/4463

Removed Features
~~~~~~~~~~~~~~~~

- Remove the secondary validator in query.c.

  Previously, when the additional section of a response was being
  populated, if cached data was found with pending trust, it would be
  opportunistically validated. The code implementing this validation was
  not quite formally correct. Rather than fixing it, the code has been
  removed: RRsets with pending trust are now omitted from responses.
  :gl:`#5966` :gl:`#5968` :gl:`#5972`

- Remove GeoIP2 `metro` and `metrocode`

  The `geoip metro` and `geoip metrocode` configuration options has been
  removed as metro code are deprecated from MaxMind library.

- Restrict views to the Internet (IN) class.

  Views could previously be declared in classes other than Internet
  (IN), but that support was inconsistent — ``named-checkconf`` accepted
  configurations that ``named`` then refused to load.  Views are now
  restricted to class IN, and both tools reject any other class.
  Configurations declaring a non-IN view must drop the class to keep
  working.

Feature Changes
~~~~~~~~~~~~~~~

- Introduce a minimum TTL for cached delegations.

  Delegations are now cached with a minimum TTL of 60 seconds by
  default. Any NS record or A/AAAA glue record with a TTL below this
  threshold will be raised to 60 seconds.

  A new configuration option `min-delegation-ttl` has been added to
  adjust this limit, or disable it by setting the value to `0`. The
  corresponding `max-delegation-ttl` option allows the user to configure
  a maximum TTL for delegations; it is disabled by default. :gl:`#6031`

Bug Fixes
~~~~~~~~~

- Fix recursion loop in case of badly behaving forwarders.

  When forwarding DNS queries, the CD bit is cleared on the first query,
  and the CD bit is only used as a fallback if the first query fails.
  However, due to a logic bug this could lead to an unbounded loop
  re-sending the same message, until the maximum query count is hit.
  This has been fixed. :gl:`#5804`

- Fix a bug in DNS UPDATE processing with inline-signing enabled.

  In rare cases the :iscman:`named` process could terminate unexpectedly
  when processing authorized DNS UPDATE messages in quick procession
  which are updating a zone with inline-signing enabled. This has been
  fixed. :gl:`#5816`

- Properly detect private records before copying.

  We were triggering an assertion when trying to copy a private record
  to a buffer for modifying.  Extend the private type detection and copy
  the contents after we have rejected invalid private records.
  :gl:`#5857`

- Tighten  referral DS acceptance.

  Named was accepting DS records for sibling zones when it shouldn't
  have.  This has been fixed. :gl:`#5870`

- Don't synthesize negative responses with pending NSEC.

  If an NSEC record has not yet been validated and is cached with trust
  pending, don't use it to synthesize negative responses. :gl:`#5872`
  :gl:`#5887`  :gl:`#5977`

- Check that an NSEC signer is at or above the name to be validated.

  Add a check that an NSEC record being used as a proof of nonexistence
  for a given name is not signed by a name lower in the DNS hierarchy
  than the one in question. :gl:`#5876`

- Don't evict DNSSEC-validated cache data on a CD=1 NXDOMAIN.

  When a client sent a query with the checking-disabled (CD) bit set and
  the answer was NXDOMAIN, the resolver cached that unvalidated negative
  response and discarded any DNSSEC-validated records it already held
  for the same name, even though the validated data was more
  trustworthy. A single such response - including a forged one - could
  flush validated records from the cache and force the resolver to fetch
  them again. The resolver now checks the trust level of the existing
  data first and leaves the cache unchanged when it is already
  validated. :gl:`#5877`

- Fix a 'deny-answer-aliases' configuration bypass issue.

  It was possible to use a maliciously crafted authoritative zone to
  make :iscman:`named` resolver synthesize a ``DNAME`` "alias" that
  should have been rejected by the configured :any:`deny-answer-aliases`
  option. This has been fixed. :gl:`#5930`

- Reject external referrals from forwarders.

  Under `forward-first` policy in a forwarding zone BIND could accept NS
  above the forward zone apex from negative responses. This has been
  fixed.

  ISC would like to thank Qifan Zhang, of Palo Alto Networks, for the
  report. :gl:`#5937`

- Fix a zone transfer over TLS (XoT) issue when using the opportunistic
  TLS mode.

  The :iscman:`named` process, running as secondary DNS server,
  configured to transfer a zone from a primary server using an encrypted
  XoT transport in opportunistic TLS mode (i.e. without peer
  certificate/hostname validation) could terminate unexpectedly when the
  TLS ALPN negotiation with primary server was unsuccessful. This has
  been fixed. :gl:`#5957`

- Unvalidated opt-out NSEC3 could be accepted in insecurity proof.

  When determining whether an insecure delegation is legitimate, NSEC3
  opt-out records which had not yet passed validation could be used.
  This has been fixed. :gl:`#5970`

- Check wildcard signer and NOQNAME signer match.

  A positive wildcard answer, and the NSEC3 proof that the requested
  name doesn't exist in the zone, must both be from the same zone.
  Otherwise, an NSEC3 from an ancestor zone could be used to interfere
  with validation.

  We now retrieve the signer name from a wildcard response's signature.
  An NSEC3 record cannot be used as a NOQNAME proof for the wildcard
  unless it exactly matches the name one level above the NSEC3.
  :gl:`#5971`

- Fix CNAME resolution failure caused by a cached SERVFAIL response.

  Under certain circumstances, a cached SERVFAIL response could
  incorrectly prevent successful resolution of a CNAME target. This
  could cause resolution failures to persist until the cached SERVFAIL
  entry expired, even when the CNAME target itself was otherwise
  resolvable. This issue has been fixed. :gl:`#5983`

- [CVE-2026-13204] Prevent crash from malformed NSEC/NSEC3 response.

  An assertion could be triggered by an improperly signed NOQNAME proof.
  This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5985`

- Reject unsupported RSA DNSKEY shapes during DNSSEC validation.

  An authoritative server publishing an RSA DNSKEY with an unusually
  large modulus or an exotic public exponent could make each DNSSEC
  signature check on a validating recursive resolver noticeably more
  expensive than for a normally sized key.  Such DNSKEYs are now treated
  as invalid. :gl:`#6008`

- Fix a bug in GeoIP2 string matching.

  When using GeoIP2 ACLs (see :any:`acl`), :iscman:`named` could
  incorrectly match a name using a sub-string instead of the full name
  match. This has been fixed. :gl:`#6019`

- Fix DNS-over-HTTPS (DoH) quota configuration issue.

  The :any:`http-listener-clients` and
  :any:`http-streams-per-connection` configuration options could be
  truncated to smaller values (or to ``0``, which means unlimited) when
  very big configuration values were used, which exceeded ``65535``. As
  a note - it is very unlikely that such big values are used in
  production, and the default values for the affected options are
  ``300`` and ``100``, correspondingly. This has been fixed. :gl:`#6021`

- Truncated reply to a TSIG query no longer stalls the resolver.

  When an upstream server returned a truncated reply to a query that
  BIND had signed with TSIG, the resolver could keep waiting for a
  follow-up UDP packet that never arrived, so the query stalled until it
  hit resolver-query-timeout and the client received no answer. BIND now
  treats any reply it cannot authenticate as an immediate failure and
  returns SERVFAIL right away as a defense in depth. :gl:`#6028`

- Ignore updates removing DNSKEY RRset with class ANY.

  When a Dynamic Update is received that removes the ``DNSKEY`` (or
  ``CDNSKEY``, or ``CDS``) RRset, remove all records except the ones
  that are in use for signing for the zone. :gl:`#6045`

- Do not assert on synthrecord reverse mode with huge prefix.

  When using the `synthrecord` plugin in reverse mode, if a very long
  prefix is configured by the operator such that there is no room to fit
  the reversed IP address into a DNS name, `named` could assert. This
  has now been fixed. In such situations, an error is logged so the
  operator is aware of the problem, and `NXDOMAIN` is answered.
  :gl:`#6115`

- Validate query and response time nanosecs when parsing dnstap.

  An assertion is triggered inside `isc_time_set` when dnstap-read calls
  `dns_dt_parse` on dnstap files with query/response time nanosecond
  fields greater than a second.

  Avoid the assertion by validating the nanosecond fields to be
  subsecond when parsing. :gl:`#6123`

- Ignore 0-byte reads in the TCP read callback.

  Callbacks for libuv stream reads do not signal zero-length reads as a
  failure signal but rather as EAGAIN/EWOULDBLOCK. This can trigger an
  assertion when a zero-length read is pushed onto a PROXYv2 endpoint
  that has not yet processed the headers as it expects a non-NULL region
  of positive length. :gl:`#6140`

- Only print per zone glue stats when query statistics is full.

  The code printing query statistics was ignoring the zone-statistics
  option. This has been fixed. :gl:`#6164`

- CDS/CDNSKEY records were not removed when re-configuring the server.

  When on an ``rndc reconfig`` the DNSSEC policy changes such that it
  changes the expected ``CDNSKEY`` and/or ``CDS`` records in the zone,
  the RRset should be updated accordingly. This did not happen when
  removing digests from the configuration, or setting `cdnskey no;`.
  This has been fixed. :gl:`#6166`

- Stop reusing outgoing TCP connections the peer has already closed.

  ``named`` could hand a new query an idle forwarder/upstream TCP or TLS
  connection that the peer had already closed, causing the query to fail
  (and CLOSE-WAIT sockets to pile up). Idle reused connections are now
  watched, so a close is noticed and the connection is dropped instead
  of reused. A new ``tcp-reuse-timeout`` option controls how long an
  idle outgoing connection is kept open for reuse (default 5 seconds).
  :gl:`#6171`

- Fix DNSSEC validation failures for names under an apex DNAME.

  DNSSEC validation could fail with SERVFAIL for names covered by a
  DNAME at the apex of a signed zone, unless the zone's keys were
  already validated in the cache. This regression was introduced by the
  recent fix for resolver stalls on CNAME responses to DS queries.
  :gl:`#6176`

- Resolver could terminate unexpectedly when processing a malformed
  RRSIG.

  A recursive resolver could terminate unexpectedly when an
  authoritative server returned a crafted RRSIG(RRSIG) record for an
  insecure zone. Such records are now rejected. :gl:`#6184`

- Cache glue only for enabled address families.

  When caching delegation NS data, only use A/AAAA glue records if the
  resolver has the corresponding IPv4/IPv6 dispatcher configured. If
  IPv4 or IPv6 is disabled, ignore glue for that family and fall back to
  caching the nameserver name if there is no glue from the other
  supported family.


