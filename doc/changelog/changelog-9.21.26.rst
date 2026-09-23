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

BIND 9.21.26
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-19668] Prevent excessive CPU use validating crafted DNSSEC
  responses. ``8d660756e8``

  A malicious authoritative server could serve a securely delegated zone
  whose DS and DNSKEY records carry many distinct key tags but no valid
  match, forcing a validating resolver into excessive key-tag matching
  and high CPU use for every query. BIND now bounds this work with the
  per-query validation limit (max-validations-per-fetch). :gl:`#5349`

- [CVE-2026-19033] Require a TSIG on every message of incoming zone
  transfers. ``fa351e24e2``

  BIND 9 used to accept TSIG-signed zone transfers in which some
  messages were unsigned, and processed those messages before the next
  signature could vouch for them. It now requires a TSIG on every
  message of an incoming AXFR or IXFR; all modern nameserver already
  sign every message, so no change is expected in practice. :gl:`#6062`

- [CVE-2026-77119] Prevent a DNSSEC downgrade of secure delegations via
  unrelated NSEC3. ``f76b3440b4``

  A validating resolver could be tricked into treating a secure
  delegation as unsigned and accepting forged answers for names beneath
  it, if an attacker could inject responses to its queries. Such forged
  proofs are now rejected. :gl:`#6234`

- [CVE-2026-19941] Prevent forged DNSSEC-validated NXDOMAIN responses.
  ``4fbd4cdc43``

  A validating resolver could accept a signed NSEC record from an
  unrelated zone as proof that a wildcard did not exist. An on-path
  attacker or malicious forwarder controlling a signed zone could
  therefore forge an authenticated NXDOMAIN response for a name that
  should resolve through a wildcard. BIND now requires the
  wildcard-denial and name-nonexistence proofs to be signed by the same
  zone. :gl:`#6253`

- [CVE-2026-19666] DNS64 with break-dnssec could cause an assertion
  failure. ``49298991b2``

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
  dns_rdata_t. ``a812d252ea``

  A single crafted response from a server could make a resolver cache a
  malformed negative entry and then terminate with an assertion failure
  when reading it back. Only recursive resolvers are affected, on a
  default configuration. :gl:`#6302`

- [CVE-2026-75029] Discard repeated SOA, CNAME, and DNAME records when
  parsing DNS messages. ``905f6cc0a3``

  A DNS message could carry the same SOA, CNAME, or DNAME record many
  times, and named kept every copy while parsing it. With name
  compression those copies took up far more memory internally than in
  the message itself, and every later processing step had to handle all
  of them. named now keeps the first copy of such a record and discards
  identical repeats. :gl:`#6335`

- [CVE-2026-77692] Fix an unauthenticated crash on HTTPS using SIG(0)
  ``d1c2532350``

  A specifically crafted HTTPS query using SIG(0) as authentication
  could crash named if the client closes the connection before named
  actually verifies the signature. This is now fixed. :gl:`#6343`

- [CVE-2026-81736] Cached HTTPS/SVCB aliases could exhaust resolver CPU.
  ``7fd25ab3b5``

  A recursive resolver that had cached a large set of interlinked HTTPS
  or SVCB records in alias form could be driven to do an excessive
  amount of work assembling a single response, because it followed every
  cached alias target when building the additional section. A client
  permitted to use recursion, together with an attacker-controlled zone
  used to plant the records, could repeat small queries to consume
  enough CPU to delay or deny service to other clients. The amount of
  additional processing done for one query is now bounded. :gl:`#6347`

- [CVE-2026-76163] Prevent TKEY queries from terminating named without
  global options. ``7ee30b2d7f``

  named could terminate unexpectedly when a remote client sent a TKEY
  query if the configuration did not include a global options statement.
  This has been fixed.

  ISC thanks Owais Lone (thesecguy) for reporting the issue. :gl:`#6357`

- [CVE-2026-78301] Out-of-zone records in a zone database could be
  served as authoritative. ``62e1be3cb4``

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
  NSEC3 proofs. ``49f35a0d4d``

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
  cache memory. ``8e3b2bf2b1``

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

New Features
~~~~~~~~~~~~

- Add aligned memory allocation support to isc_mem. ``134593819d``

  Restores the flags-based isc_mem_*x() API with ISC_MEM_ALIGN()
  (removed earlier as unused) so that the upcoming false-sharing fixes
  for the zone and database structures can request cache-line-aligned
  memory, honored on every allocator path including non-jemalloc builds.
  :gl:`!12512`

- Add an agent skill for the isc_job/isc_async/isc_work APIs.
  ``a7ec6a90ab``

  Documents when to use isc_job_run(), isc_async_run() or
  isc_work_enqueue(), and the contract each one imposes. No functional
  change. :gl:`!12405`

- Add constant-time DNS root-name checks. ``0877c016cb``

  Checking whether a DNS name is the root could require walking the name
  to count its labels or comparing it with the global root name. A new
  dns_name_isroot() helper checks the root wire encoding directly,
  distinguishes the empty name from the root, and replaces the existing
  ad hoc checks. :gl:`!11920`

- Add dns_name_empty() to avoid counting labels in emptiness checks.
  ``7db56119a7``

  Checking whether a DNS name is empty was done with
  dns_name_countlabels(), which walks every label in the name just to
  compare the count with zero. The new dns_name_empty() helper checks
  the name's length directly, and a coccinelle patch converts the
  existing callers. :gl:`!12558`

- Use more compiler-specific attributes. ``05ea5490c6``

  Use more GCC and clang specific attributes. While `counted_by` is the
  main target, others are planned to be used more aggressively in the
  future. :gl:`!12480`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the RFC 1918 reverse-lookup leakage warning. ``8f7874ed58``

  When default empty zones are disabled, ``named`` would log an
  unthrottled warning for every reverse (PTR) lookup of an RFC 1918
  address that returned NXDOMAIN from the Internet. This warning has
  been removed. :gl:`!12312`

Feature Changes
~~~~~~~~~~~~~~~

- Reject oversized and malformed DNSKEY records up front. ``68f2385175``

  Oversized RSA key material in a DNSKEY record was only rejected after
  it had been converted, allocating memory proportional to the record
  size. Such records are now rejected before conversion, as are Ed25519
  and Ed448 keys with trailing bytes that were previously silently
  ignored. :gl:`#4537` :gl:`!12544`

- Reject out-of-zone records in zone transfers and zone files.
  ``2d8fda350b``

  A secondary server accepted any owner name a primary included in an
  AXFR or IXFR, so records that did not belong under the zone's apex
  were stored in the zone database and could be loaded again later from
  the saved zone file; the dnssec-signzone and dnssec-verify utilities
  were similarly lenient with zone files. Zone transfers, saved
  secondary zone files, and zone files processed by the DNSSEC tools are
  now all rejected as malformed when they contain out-of-zone records.
  :gl:`#5842` :gl:`!12627`

- Add a zone delegation specific query path. ``483f724eb8``

  Split the handling of delegations into a zone and cache specific
  paths, in order to improve scalability in the zone path. As a
  consequence we need to tweak the hooks and dyndb API requirements.
  :gl:`!12418`

- Prevent false sharing by aligning some zone and db fields.
  ``0034781fbf``

  The zone refcount, zone dblock, db refcount and db lock are pretty
  contended in setups serving few big zones, such as TLDs.

  We add alignment to both in order to prevent false sharing between
  them. :gl:`!12513`

- Remove nodep from the dns_db_find() API. ``2c0c3bf87c``

  Previously `dns_db_find()` return four values: a result, an rdataset,
  the name of the rdataset and a pointer to the node containing the
  rdataset (`nodep`). With a few tweaks the node pointer can be made
  superflous, as the node can be retrieved from the rdataset name using
  `dns_db_findnode()`.

  This MR removes the `nodep` output parameter from `dns_db_find()`,
  leading both an API simplification and speedups when serving NSEC
  signed zones. :gl:`!12458`

- Root hints are now stored into the delegdb. ``0caf8955e7``

  The root hints are now stored inside the delegation database. The
  `rootdb` which was previously used to store them is now removed (as
  well as the associated code) from the whole codebase. :gl:`!12472`

- Sharded client udp refcounts. ``aa9dd3d96c``

  All listening clients would try to attach to the same listening
  socket. By making the clients attach to the underlying sockets instead
  we can substantially reduce contention. :gl:`!12471`

Bug Fixes
~~~~~~~~~

- Prevent a crash when using both dns64 and filter-a. ``9d34e3b511``

  An assertion failure was possible when using both `dns64` and the
  `filter-a` plugin simultaneously; this has been fixed. :gl:`#5979`
  :gl:`!12280`

- Prevent overwriting an existing iptable node when merging.
  ``dfa9967150``

  Previously, if an ACL was misconfigured with a duplicate entry in a
  negated nested ACL, like this:

  { 10.9.8.1; ! { 10.9.8.1; }; }

  ... the first-match node for 10.9.8.1 would have been reversed,
  producing the effective ACL:

  { !10.9.8.1; };

  This has been corrected by modifying `isc_radix_insert()`. Radix
  insertion cannot fail, and previously the function had no return
  value. But it actually has two different success cases: one in which
  it has created a new radix node, and one in which it has found an
  existing node with a matching prefix and passed back a pointer to it.
  To distinguish between these, it now returns either `ISC_R_SUCCESS` or
  `ISC_R_EXISTS`.

  `dns_iptable_merge()` uses this to ensure that existing nodes won't be
  overwritten by subsequently-specified ones. :gl:`#6049` :gl:`!12407`

- Fix update-policy grant external address passing. ``dc55e59814``

  Only TCP client addresses are supposed to be passed to an `external`
  handler for the associated `update-policy` rule, but UDP client
  addresses were also being passed.  This could have caused the external
  handler to return a result it otherwise wouldn't. This has been fixed.
  :gl:`#6061` :gl:`!12546`

- Missing required NSEC3 for delegation not detected. ``e703168fdb``

  A missing required NSEC3 record for an insecure delegation in a non
  OPTOUT range was not being detected.  This has been fixed. :gl:`#6063`
  :gl:`!12495`

- Tighten EUI48 and EUI48 text parsing. ``47aa58d291``

  Malformed EUI48 and EUI64 records could be accepted.  This has been
  fixed. :gl:`#6082` :gl:`!12490`

- GeoIP ACL state can be stale or wrong after reload. ``e7b9f4e9c5``

  `named` caches GeoIP information after looking it up, but the cached
  information was not invalidated when the GeoIP database was reloaded,
  so it could continue to be used.  We now invalidate existing cached
  GeoIP information as part of the reloading process. :gl:`#6083`
  :gl:`!12550`

- Honor DNSSEC policy key tag ranges. ``05b463c2cc``

  When a DNSSEC policy configured a non-default tag-range, dnssec-keygen
  and dnssec-ksr could accept generated keys outside that range. Both
  tools now honor the configured minimum and maximum key tags.
  :gl:`#6091` :gl:`!12539`

- Fix double free in mdig when EDNS options are specified.
  ``097826e7f9``

  When the default_query is cloned the EDNS options need to be cloned
  rather than the pointer copied.  The old behaviour results in a double
  free of the options.  This has been fixed. :gl:`#6095` :gl:`!12594`

- Fix a crash when an IXFR falls back to AXFR with updates still
  pending. ``ef33a37d04``

  When a secondary zone received an incremental transfer (IXFR) and the
  primary then caused named to fall back to a full transfer (AXFR) while
  some of the already-received incremental changes were still waiting to
  be applied, named could later crash when that transfer finished. The
  pending changes are now discarded correctly before the AXFR retry.
  :gl:`#6114` :gl:`!12610`

- Fix DS requests to parental agents over TLS. ``794e125be6``

  TLS configuration for parental agents was being ignored when sending
  DS requests. This has been fixed. :gl:`#6135` :gl:`!12433`

- Rndc-confgen `-q` (quiet) option is documented but doesn't work.
  ``51d4823b8c``

  The command line parsing in rndc-confgen was broken so  `rndc-confgen
  -q` did not work.  This has been fixed. :gl:`#6187` :gl:`!12570`

- Enforce query ACLs for redirect zones and searched DLZs.
  ``7d5df2ff74``

  Queries answered from redirect zones or searched DLZ databases did not
  consistently honor `allow-query` and `allow-query-on`, potentially
  exposing restricted DNS data to excluded clients or through excluded
  listening addresses. These ACLs are now enforced before redirect or
  DLZ data is returned. :gl:`#6251`, #6252 :gl:`!12634`

- Check "asnum" validity in GeoIP ACLs. ``9667b263df``

  We now check the validity of autonomous system (AS) numbers when
  parsing GeoIP ACLs that use `asnum` elements at configuration time.

  `asnum` values start with an optional case-insensitive "AS" prefix,
  followed only by decimal digits, with no spaces or other extraneous
  characters. The value represented cannot exceed 2^32. :gl:`#6255`
  :gl:`!12438`

- Prevent crashes while reporting DNSSEC signing statistics.
  ``1a95c99def``

  Servers with zone-statistics full could terminate while reporting
  DNSSEC signing statistics for a zone tracking adding more than four
  signing keys. :gl:`#6256` :gl:`!12540`

- Fix various nits in the netmgr code. ``4ed080475f``

  The MR consists of couple of small fixes and uncaught errors in the
  Network Manager. :gl:`#6257` :gl:`!11639`

- Fix a crash on remote-servers lists that reference themselves.
  ``8d6c984993``

  Since 9.21.16 and 9.20.17, a remote-servers, primaries, masters, or
  parental-agents list that referenced itself, directly or through
  another list, made named crash on startup or reconfiguration. Such
  references are again skipped and the remaining entries in the list are
  used, as in earlier versions. :gl:`#6287` :gl:`!12506`

- A record from outside a response policy zone could stop named.
  ``8e40f0b39f``

  A response policy zone transferred from a primary can contain a record
  whose name lies outside the zone. Such a record could stop named, both
  when it arrived and again at every startup afterwards, because a
  secondary keeps it in its own copy of the zone. Records like this are
  now rejected and logged; previously one could also silently create a
  policy entry for an unrelated name. :gl:`#6304` :gl:`!12522`

- "rndc flushtree ." failed to flush the cache. ``143dee174e``

  `rndc flushtree` flushes cache data below a specified name. If the
  name specified is the DNS root, it should fully empty the cache, the
  same as `rndc flush`.  However, there was a bug causing the command,
  in that case, to have no effect on the cache at all; this has been
  fixed. :gl:`#6308` :gl:`!12579`

- Invalid key-store configuration could abort the DNSSEC tools.
  ``aef8af2bf5``

  Invalid configured key-stores named "key-directory" in configuration
  files could abort the DNSSEC tools. This has been fixed. :gl:`#6313`
  :gl:`!12619`

- Fix crash in named-checkconf -n. ``2e20bf3e93``

  The `named-checkconf -n` option always triggered a crash due to an
  incorrect `REQUIRE`. This has been fixed, and a regression test added
  to the `checkconf` system test. :gl:`#6314` :gl:`!12547`

- NSEC signature set could bypass the secure-delegation check.
  ``446a1fb39b``

  When proving that a delegation is insecure, the validator bounded an
  NSEC record's authority by the signer of whichever RRSIG happened to
  come first in the record's signature set, rather than the signature
  that actually verified. A grandparent NSEC padded with an extra,
  unverifiable signature could therefore pass the check that keeps such
  proofs from reaching below a signed child zone. The validator now
  requires every signature on the NSEC to name the same signer and
  refuses proofs whose signature set is malformed or larger than
  max-validations-per-fetch allows. :gl:`#6321`

- Fix a possible nsupdate issue when using GSS-TSIG. ``9e8d72aeb5``

  The :iscman:`nsupdate` process could terminate unexpectedly when using
  the GSS-TSIG mode executed with the :option:`nsupdate -g` option. This
  has been fixed. :gl:`#6325` :gl:`!12587`

- Fix isccc_alist_define error paths. ``2724784510``

  If there is an out of memory error in isccc_alist_define a memory leak
  (the sexpr holding the key name) or a double free (value) could occur.
  This has been fixed. :gl:`#6329` :gl:`!12592`

- Check for empty 'endpoints' list. ``b3cf0ccc6d``

  Configuring an `http` block with `endpoints {};` previously caused a
  crash in `named`. This is now rejected earlier by the configuration
  check. :gl:`#6330` :gl:`!12548`

- Construct hashed filenames with buffers. ``2db23b5130``

  The reused buffer in dns_catz_generate_masterfilename() could cause a
  process abort when built with '_FORTIFY_SOURCE=3' because of the
  recently introduced 'ISC_ATTR_COUNTED_BY_PTR(length)' compiler runtime
  check.

  Refactor hashed filenames construction code to use buffers, also
  refactor isc_md_digest2hex() to use isc_hex_totextlower() instead of
  snprintf() for hex conversion. :gl:`#6360` :gl:`!12623`

- Fix named-checkconf/named crash with malformed key name.
  ``0480bfe3f2``

  When a primary/remote-server key name was malformed, named-checkconf
  and named were both crashing (after warning about the invalid key
  name). This is now fixed. :gl:`#6362` :gl:`!12635`

- Fix multiple configuration parser crashes. ``2c09bb6704``

  Multiples issues were affecting the configuration checker in case of
  invalid configuration which could lead to crashes of `named-checkconf`
  and `named`: malformed zone name when the DB file name is using a
  template, and malformed configuration file (unexpected EOF).

  Those are now fixed. :gl:`#6364`, #6363 :gl:`!12628`

- Fix -Wformat-truncation warning in totext_in_wks() ``d777c06852``

  BIND 9 failed to build with GCC 16 at -O3: rendering a WKS record as
  text triggered a -Wformat-truncation error, which is fatal in
  developer builds. The port number is now printed with a 16-bit format
  specifier, so the compiler can see it always fits the output buffer.
  :gl:`!12519`

- Fix off-by-one errors caused by magic hardcoded values. ``7fbeb295b0``

  Fix off-by-one comparinson errors: "named -p http=" dropped the first
  digit of the given port (for example, "http=8080" selected port 80)
  and now uses the port as given, and "named-rrchecker -C" compared only
  part of the "CLASS" prefix when filtering generic class names, which
  was harmless in practice but is now corrected. :gl:`!12614`

- Fix shutdown crash when DLZ instances are in use. ``0f13f5a00e``

  Previously, `named` could crash during shutdown when DLZ instance were
  used because of a user-after-free. This is now fixed. :gl:`!12644`

- Hmac_verify() now accepts truncated HMACs only when requested.
  ``bf74540dfe``

  The hmac_verify() function incorrectly compares only up to
  'sig->length' bytes, but the signature and its length should not be
  trusted, e.g. in case if it comes from a user query.

  Don't accept signatures which length isn't equal to the expected
  calculated HMAC length unless it is explicitly requested by the
  caller, e.g. for truncated TSIG [1] support. :gl:`!12612`

  [1] https://datatracker.ietf.org/doc/html/rfc8945#name-tsig-truncation-policy

- Minor refactoring of query_usestale() ``65fe7ddf2e``

  Due to previous changes, the result code passed to `query_usestale()`
  is now only used for one thing: the function returns immediately if
  the result is `DNS_R_DROP` or `DNS_R_DUPLICATE`.

  We now no longer pass the result code to `query_usestale()` at all;
  the calling function checks the result instead of calling it.
  :gl:`!12444`

- Prevent resolver crashes while processing DNS over TCP. ``ffe413b2ec``

  Recursive resolvers could terminate with an assertion failure while
  processing DNS responses over TCP under sustained traffic. The failure
  was observed on resolvers configured globally with forward only; the
  same transport path is also used by iterative resolution.  This has
  been fixed. :gl:`!12536`

- Query a resolver with RD=0 and no cache hit returns SERVFAIL.
  ``3290f7efe0``

  When a resolver is queried with RD=0 and there is no cache hit for the
  queried query name, SERVFAIL is now returned instead of
  NOERROR/NODATA.

  This also fixes an issue where, in that situation, root hints were
  wrongly returned in the AUTHORITY section.

  Note that if the resolver is also authoritative for a zone which can
  answer or send a referral, NOERROR is still returned with appropriate
  ANSWER/AUTHORITY/ADDITIONAL sections. :gl:`!12222`

- Use alignas() from stdatomics to align. ``0c6fb399b9``

  This is a followup to !12513 that missed two fixup commits that
  changed __attribute__((__aligned__(N))) to alignas() :gl:`!12578`


