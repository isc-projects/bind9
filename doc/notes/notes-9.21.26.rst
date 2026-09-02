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

Notes for BIND 9.21.26
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-19668] Prevent excessive CPU use validating crafted DNSSEC
  responses.

  A malicious authoritative server could serve a securely delegated zone
  whose DS and DNSKEY records carry many distinct key tags but no valid
  match, forcing a validating resolver into excessive key-tag matching
  and high CPU use for every query. BIND now bounds this work with the
  per-query validation limit (max-validations-per-fetch). :gl:`#5349`

- [CVE-2026-19033] Require a TSIG on every message of incoming zone
  transfers.

  BIND 9 used to accept TSIG-signed zone transfers in which some
  messages were unsigned, and processed those messages before the next
  signature could vouch for them. It now requires a TSIG on every
  message of an incoming AXFR or IXFR; all modern nameserver already
  sign every message, so no change is expected in practice. :gl:`#6062`

- [CVE-2026-77119] Prevent a DNSSEC downgrade of secure delegations via
  unrelated NSEC3.

  A validating resolver could be tricked into treating a secure
  delegation as unsigned and accepting forged answers for names beneath
  it, if an attacker could inject responses to its queries. Such forged
  proofs are now rejected. :gl:`#6234`

- [CVE-2026-19941] Prevent forged DNSSEC-validated NXDOMAIN responses.

  A validating resolver could accept a signed NSEC record from an
  unrelated zone as proof that a wildcard did not exist. An on-path
  attacker or malicious forwarder controlling a signed zone could
  therefore forge an authenticated NXDOMAIN response for a name that
  should resolve through a wildcard. BIND now requires the
  wildcard-denial and name-nonexistence proofs to be signed by the same
  zone. :gl:`#6253`

- [CVE-2026-19666] DNS64 with break-dnssec could cause an assertion
  failure.

  When a "dns64" statement is configured with "break-dnssec yes" and its
  "exclude" list matches some but not all of the addresses in an AAAA
  RRset, named removes the excluded addresses from the answer instead of
  synthesizing new ones. If the answer being filtered had been cached
  together with a proof that the queried name does not exist -- which is
  what a wildcard match produces -- named terminated with an assertion
  failure.

  Only recursive resolvers are affected, and only when "break-dnssec
  yes" is in use; the answer has to come from the cache, so a server
  that is only authoritative cannot reach this. :gl:`#6301`

- [CVE-2026-19667] Reject negative cache records that do not fit in a
  dns_rdata_t.

  A single crafted response from a server could make a resolver cache a
  malformed negative entry and then terminate with an assertion failure
  when reading it back. Only recursive resolvers are affected, on a
  default configuration. :gl:`#6302`

- [CVE-2026-75029] Discard repeated SOA, CNAME, and DNAME records when
  parsing DNS messages.

  A DNS message could carry the same SOA, CNAME, or DNAME record many
  times, and named kept every copy while parsing it. With name
  compression those copies took up far more memory internally than in
  the message itself, and every later processing step had to handle all
  of them. named now keeps the first copy of such a record and discards
  identical repeats. :gl:`#6335`

- [CVE-2026-77692] Fix an unauthenticated crash on HTTPS using SIG(0)

  A specifically crafted HTTPS query using SIG(0) as authentication
  could crash named if the client closes the connection before named
  actually verifies the signature. This is now fixed. :gl:`#6343`

- [CVE-2026-81736] Cached HTTPS/SVCB aliases could exhaust resolver CPU.

  A recursive resolver that had cached a large set of interlinked HTTPS
  or SVCB records in alias form could be driven to do an excessive
  amount of work assembling a single response, because it followed every
  cached alias target when building the additional section. A client
  permitted to use recursion, together with an attacker-controlled zone
  used to plant the records, could repeat small queries to consume
  enough CPU to delay or deny service to other clients. The amount of
  additional processing done for one query is now bounded. :gl:`#6347`

- [CVE-2026-76163] Prevent TKEY queries from terminating named without
  global options.

  named could terminate unexpectedly when a remote client sent a TKEY
  query if the configuration did not include a global options statement.
  This has been fixed.

  ISC thanks Owais Lone (thesecguy) for reporting the issue. :gl:`#6357`

- [CVE-2026-78301] Out-of-zone records in a zone database could be
  served as authoritative.

  When a zone database contained records for names outside the zone —
  such as a delegation above the zone apex, left behind by a secondary
  that had accepted out-of-zone data from its primary — the server could
  treat them as authoritative and answer queries for names inside the
  zone with that out-of-zone data instead of the zone's own. A server
  that was also a resolver could follow such a delegation and cache the
  answers of the server it named, affecting names outside the configured
  zone. Zone database lookups are now confined to names at or below the
  zone's origin.

  ISC would like to thank Henrique Pereira for reporting the issue.
  :gl:`#6361`

- [CVE-2026-80274] Crash on wildcard answers carrying both NSEC and
  NSEC3 proofs.

  When a wildcard answer arrived with both NSEC and NSEC3 records at the
  name proving that the queried name does not exist, the resolver could
  pick different records when caching the answer and when retrieving the
  proof, depending on the order in which the authoritative server sent
  them. This could terminate named with an assertion failure, fail the
  query with SERVFAIL, or serve a denial record other than the one that
  had been verified. The resolver now caches and serves the same denial
  record it accepted when the answer was received.

  ISC would like to thank hythyt for reporting the issue. :gl:`#6369`

- [CVE-2026-81563] Following HTTPS/SVCB aliases could leak resolver
  cache memory.

  When a recursive server answered a query for an HTTPS or SVCB record
  in alias form and the alias target had more than 13 records, the
  target records were pinned in the cache permanently instead of being
  released once the answer was sent. A remote party who could make the
  server follow such aliases to a steady stream of fresh names could
  grow the cache beyond the configured max-cache-size until the server
  was unable to resolve unrelated names. The records are now released
  correctly.

  ISC would like to thank Samy Medjahed/Ap4sh for reporting the issue.
  :gl:`#6374`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the RFC 1918 reverse-lookup leakage warning.

  When default empty zones are disabled, ``named`` would log an
  unthrottled warning for every reverse (PTR) lookup of an RFC 1918
  address that returned NXDOMAIN from the Internet. This warning has
  been removed.

Feature Changes
~~~~~~~~~~~~~~~

- Reject oversized and malformed DNSKEY records up front.

  Oversized RSA key material in a DNSKEY record was only rejected after
  it had been converted, allocating memory proportional to the record
  size. Such records are now rejected before conversion, as are Ed25519
  and Ed448 keys with trailing bytes that were previously silently
  ignored. :gl:`#4537`

- Reject out-of-zone records in zone transfers and zone files.

  A secondary server accepted any owner name a primary included in an
  AXFR or IXFR, so records that did not belong under the zone's apex
  were stored in the zone database and could be loaded again later from
  the saved zone file; the dnssec-signzone and dnssec-verify utilities
  were similarly lenient with zone files. Zone transfers, saved
  secondary zone files, and zone files processed by the DNSSEC tools are
  now all rejected as malformed when they contain out-of-zone records.
  :gl:`#5842`

Bug Fixes
~~~~~~~~~

- Prevent a crash when using both dns64 and filter-a.

  An assertion failure was possible when using both `dns64` and the
  `filter-a` plugin simultaneously; this has been fixed. :gl:`#5979`

- Fix update-policy grant external address passing.

  Only TCP client addresses are supposed to be passed to an `external`
  handler for the associated `update-policy` rule, but UDP client
  addresses were also being passed.  This could have caused the external
  handler to return a result it otherwise wouldn't. This has been fixed.
  :gl:`#6061`

- Missing required NSEC3 for delegation not detected.

  A missing required NSEC3 record for an insecure delegation in a non
  OPTOUT range was not being detected.  This has been fixed. :gl:`#6063`

- Tighten EUI48 and EUI48 text parsing.

  Malformed EUI48 and EUI64 records could be accepted.  This has been
  fixed. :gl:`#6082`

- GeoIP ACL state can be stale or wrong after reload.

  `named` caches GeoIP information after looking it up, but the cached
  information was not invalidated when the GeoIP database was reloaded,
  so it could continue to be used.  We now invalidate existing cached
  GeoIP information as part of the reloading process. :gl:`#6083`

- Honor DNSSEC policy key tag ranges.

  When a DNSSEC policy configured a non-default tag-range, dnssec-keygen
  and dnssec-ksr could accept generated keys outside that range. Both
  tools now honor the configured minimum and maximum key tags.
  :gl:`#6091`

- Fix double free in mdig when EDNS options are specified.

  When the default_query is cloned the EDNS options need to be cloned
  rather than the pointer copied.  The old behaviour results in a double
  free of the options.  This has been fixed. :gl:`#6095`

- Fix a crash when an IXFR falls back to AXFR with updates still
  pending.

  When a secondary zone received an incremental transfer (IXFR) and the
  primary then caused named to fall back to a full transfer (AXFR) while
  some of the already-received incremental changes were still waiting to
  be applied, named could later crash when that transfer finished. The
  pending changes are now discarded correctly before the AXFR retry.
  :gl:`#6114`

- Fix DS requests to parental agents over TLS.

  TLS configuration for parental agents was being ignored when sending
  DS requests. This has been fixed. :gl:`#6135`

- Rndc-confgen `-q` (quiet) option is documented but doesn't work.

  The command line parsing in rndc-confgen was broken so  `rndc-confgen
  -q` did not work.  This has been fixed. :gl:`#6187`

- Enforce query ACLs for redirect zones and searched DLZs.

  Queries answered from redirect zones or searched DLZ databases did not
  consistently honor `allow-query` and `allow-query-on`, potentially
  exposing restricted DNS data to excluded clients or through excluded
  listening addresses. These ACLs are now enforced before redirect or
  DLZ data is returned. :gl:`#6251`, #6252

- Check "asnum" validity in GeoIP ACLs.

  We now check the validity of autonomous system (AS) numbers when
  parsing GeoIP ACLs that use `asnum` elements at configuration time.

  `asnum` values start with an optional case-insensitive "AS" prefix,
  followed only by decimal digits, with no spaces or other extraneous
  characters. The value represented cannot exceed 2^32. :gl:`#6255`

- Fix a crash on remote-servers lists that reference themselves.

  Since 9.21.16 and 9.20.17, a remote-servers, primaries, masters, or
  parental-agents list that referenced itself, directly or through
  another list, made named crash on startup or reconfiguration. Such
  references are again skipped and the remaining entries in the list are
  used, as in earlier versions. :gl:`#6287`

- A record from outside a response policy zone could stop named.

  A response policy zone transferred from a primary can contain a record
  whose name lies outside the zone. Such a record could stop named, both
  when it arrived and again at every startup afterwards, because a
  secondary keeps it in its own copy of the zone. Records like this are
  now rejected and logged; previously one could also silently create a
  policy entry for an unrelated name. :gl:`#6304`

- Invalid key-store configuration could abort the DNSSEC tools.

  Invalid configured key-stores named "key-directory" in configuration
  files could abort the DNSSEC tools. This has been fixed. :gl:`#6313`

- NSEC signature set could bypass the secure-delegation check.

  When proving that a delegation is insecure, the validator bounded an
  NSEC record's authority by the signer of whichever RRSIG happened to
  come first in the record's signature set, rather than the signature
  that actually verified. A grandparent NSEC padded with an extra,
  unverifiable signature could therefore pass the check that keeps such
  proofs from reaching below a signed child zone. The validator now
  requires every signature on the NSEC to name the same signer and
  refuses proofs whose signature set is malformed or larger than
  max-validations-per-fetch allows. :gl:`#6321`

- Fix a possible nsupdate issue when using GSS-TSIG.

  The :iscman:`nsupdate` process could terminate unexpectedly when using
  the GSS-TSIG mode executed with the :option:`nsupdate -g` option. This
  has been fixed. :gl:`#6325`

- Fix isccc_alist_define error paths.

  If there is an out of memory error in isccc_alist_define a memory leak
  (the sexpr holding the key name) or a double free (value) could occur.
  This has been fixed. :gl:`#6329`

- Fix named-checkconf/named crash with malformed key name.

  When a primary/remote-server key name was malformed, named-checkconf
  and named were both crashing (after warning about the invalid key
  name). This is now fixed. :gl:`#6362`

- Fix multiple configuration parser crashes.

  Multiples issues were affecting the configuration checker in case of
  invalid configuration which could lead to crashes of `named-checkconf`
  and `named`: malformed zone name when the DB file name is using a
  template, and malformed configuration file (unexpected EOF).

  Those are now fixed. :gl:`#6364`, #6363

- Fix shutdown crash when DLZ instances are in use.

  Previously, `named` could crash during shutdown when DLZ instance were
  used because of a user-after-free. This is now fixed.

- Prevent resolver crashes while processing DNS over TCP.

  Recursive resolvers could terminate with an assertion failure while
  processing DNS responses over TCP under sustained traffic. The failure
  was observed on resolvers configured globally with forward only; the
  same transport path is also used by iterative resolution.  This has
  been fixed.

- Query a resolver with RD=0 and no cache hit returns SERVFAIL.

  When a resolver is queried with RD=0 and there is no cache hit for the
  queried query name, SERVFAIL is now returned instead of
  NOERROR/NODATA.

  This also fixes an issue where, in that situation, root hints were
  wrongly returned in the AUTHORITY section.

  Note that if the resolver is also authoritative for a zone which can
  answer or send a referral, NOERROR is still returned with appropriate
  ANSWER/AUTHORITY/ADDITIONAL sections.


