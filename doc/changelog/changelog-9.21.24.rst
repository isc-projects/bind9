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

BIND 9.21.24
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-11331] Fix handling of rpz CNAME expansion that returns name
  too long. ``dbdb8d805c9``

  Previously, if the expansion of a wildcard CNAME RPZ policy resulted
  in a name that exceeded the length limit, a self referential CNAME and
  the original address record were returned, allowing the policy to be
  bypassed.  In branches up to 9.20, this also left query processing in
  an inconsistent state which could trigger an assertion failure.  We
  now return a YXDOMAIN response, without the address.

  ISC would like to thank Laith Mash'al (0xmshal) for bringing this
  issue to our attention. :gl:`#5856`

- [CVE-2026-11721] Invalid signed wildcard records were being accepted.
  ``38c00f5e399``

  Signed wildcard responses in which the Labels field in the `RRSIG`
  record was less than the number of labels in the Signer Name field
  were being incorrectly accepted. This in turn broke
  `synth-from-dnssec`, which depends on such records being correctly
  validated. This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for bringing this issue
  to our attention. :gl:`#5871`

- [CVE-2026-13321] Fix DNSSEC validation bypass via out-of-zone NSEC
  Next Field. ``8a9bb2556ff``

  A malicious zone with out-of-zone NSEC next owner names can cause a
  DNSSEC validating resolver to cache such record and, if
  `synth-from-dnssec` is enabled, to generate negative answers for any
  zone that is covered by the range.

  ISC would like to thank Qifan Zhang of Palo Alto Networks for
  reporting the issue. :gl:`#5873`

- [CVE-2026-10723] Correct verification of NSEC3 signer name.
  ``215f1fc993f``

  BIND 9 accepted child-zone NSEC3 records where the first label equals
  the hash of the parent zone as valid parent-zone closest encloser
  proofs. This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5874`

- [CVE-2026-10822] Malformed DNSKEY records could trigger an assertion.
  ``19ec5cd27ee``

  Previously, `dns_name_fromwire()` did not honor the record boundary
  when reading names from the wire, allowing malformed records to be
  accepted when they should not have been. In particular, malformed
  DNSKEY records could trigger an assertion failure when being printed.
  This has been fixed. :gl:`#6004`

- Reclaim memory promptly when DNSSEC validations are canceled.
  ``4e5a5201f26``

  When a resolver is flooded with queries that require DNSSEC validation
  — for example during a random-subdomain attack — many of those
  validations are canceled before they complete. Previously a canceled
  validation still kept its place in the internal work queue and held
  the associated response in memory until that queued work eventually
  ran, so memory could climb sharply under sustained load. The canceled
  work is now dropped as soon as the validation is canceled, releasing
  the memory it was holding.

- [CVE-2026-11605] Prevent excessive validation work from crafted
  negative responses. ``d414f44bffa``

  A validating resolver could be made to perform a large amount of
  DNSSEC validation work in response to a single answer, consuming
  excessive CPU. A malicious authoritative server triggers this by
  returning a signed negative answer (NXDOMAIN or NODATA) padded with
  many denial-of-existence proof records, which the resolver continued
  to verify beyond its per-query validation limit. It now enforces that
  limit on negative answers and returns SERVFAIL once the limit is
  reached.

  Closes: https://gitlab.isc.org/isc-projects/bind9/-/work_items/4463

New Features
~~~~~~~~~~~~

- Print OS platform in "named -V" ``74a3c561aab``

  The "running on" line emitted by `named -V` (as well as the startup
  log and `rndc status`, which share the same source) now appends the
  PRETTY_NAME value from /etc/os-release in parentheses after the uname
  output, e.g.:

  running on Linux x86_64 6.19.14-... (Fedora Linux 42 (Workstation
  Edition))

  This helps disambiguate environments where the kernel string is not a
  reliable indicator of the userspace, such as RHEL clones and
  containers whose kernel does not match the host OS.

  When /etc/os-release is absent, /usr/lib/os-release is tried as a
  fallback per the systemd os-release(5) specification. When neither is
  available or no PRETTY_NAME is found, the output is unchanged.

  Assisted-by: Claude:claude-opus-4-7 :gl:`#5334` :gl:`!12055`

- Add DTrace support for resolver queries. ``397ade10420``

  When `fctx_query()` is called, a DTrace probe (if enabled) prints the
  fetch context address, the upstream server address and port, and the
  latest known SRTT for the server. :gl:`!12010`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the secondary validator in query.c. ``1fe179973e2``

  Previously, when the additional section of a response was being
  populated, if cached data was found with pending trust, it would be
  opportunistically validated. The code implementing this validation was
  not quite formally correct. Rather than fixing it, the code has been
  removed: RRsets with pending trust are now omitted from responses.
  :gl:`#5966` :gl:`#5968` :gl:`#5972` :gl:`!12236`

- Remove GeoIP2 `metro` and `metrocode` ``8a890e10cbb``

  The `geoip metro` and `geoip metrocode` configuration options has been
  removed as metro code are deprecated from MaxMind library.
  :gl:`!12217`

- Restrict views to the Internet (IN) class. ``edb03e2ee40``

  Views could previously be declared in classes other than Internet
  (IN), but that support was inconsistent — ``named-checkconf`` accepted
  configurations that ``named`` then refused to load.  Views are now
  restricted to class IN, and both tools reject any other class.
  Configurations declaring a non-IN view must drop the class to keep
  working. :gl:`!12163`

Feature Changes
~~~~~~~~~~~~~~~

- Introduce a minimum TTL for cached delegations. ``6588c5f304e``

  Delegations are now cached with a minimum TTL of 60 seconds by
  default. Any NS record or A/AAAA glue record with a TTL below this
  threshold will be raised to 60 seconds.

  A new configuration option `min-delegation-ttl` has been added to
  adjust this limit, or disable it by setting the value to `0`. The
  corresponding `max-delegation-ttl` option allows the user to configure
  a maximum TTL for delegations; it is disabled by default. :gl:`#6031`
  :gl:`!12102`

- Fix double initialization in copy_tuple() ``868bb66a9af``

  Small cleanup. Found with ninja -C build-dir/ scan-build.

  Patch submitted by Tim Rühsen. :gl:`#6163` :gl:`!12292`

- Disambiguate `query_cname()` and `query_dname()` usage.
  ``61c219c6dea``

  Make explicit the fact that `query_cname()` and `query_dname()` must
  be called only from a context where the resolver is answering a
  question which is _not_ respectively `CNAME` or `DNAME`.

- Follow-up of disambiguate `query_cname()` and `query_dname()` usage.
  ``424a4860025``

  Previous commit "Disambiguate `query_cname()` and `query_dname()`
  usage" was harmless but also useless, as it was checking
  `qctx->result` which is always set to `ISC_R_SUCCESS` when `qctx` is
  initialized. The intent was to check `qctx->fresp->result` (which is
  the result provided by the resolver). But this was also wrong (this is
  actually the case we do expect `query_cname()`/`query_dname()` to be
  called, to follow the chain).

  The actual invarant that needs to be checked is if the qtype is CNAME
  then we do not follow the chain, so we can't call `query_cname()`.
  This invariant has been added.

  If the qtype is DNAME, it's more complex, because a DNAME can be found
  from a local zone or cache and the chain can be locally followed. In
  which case, calling `query_dname()` is legit, as soon as the qname is
  a subname of the DNAME target. This invariant is already checked.

- Mark the related slabheader as visited on cache hit. ``1a2d276d3f1``

  A cache hit only marked the looked-up header as SIEVE-visited, leaving
  its related header (the flattened counterpart) a candidate for
  eviction. Mark both so related slabheaders age together. :gl:`!12306`

- Reference count and flatten the cache slabheader storage.
  ``42c741baa62``

  Internal refactoring of the cache database (qpcache) with no
  functional change. The slab headers that hold cached rdatasets are now
  reference counted and own their memory context and node reference
  directly, so a header can outlive the cleaning of its node and be
  reclaimed independently of it. Building on that, the per-type slabtop
  container is folded into the slab header itself, removing a level of
  indirection and one allocation per cached type. :gl:`!12285`

- Replace query and inner client attribute bitfields with named bools.
  ``2762fe12a01``

  Replace the unsigned int attributes field in struct ns_query and the
  unsigned int attributes field in struct ns_client_inner with
  individual bool bitfields. :gl:`!11732`

- Rework isc_work as per-loop, per-lane cancelable worker threads.
  ``0eb657c45b0``

  Fold the libuv thread pool and the per-loop isc_helper threads into a
  single isc_work pool. Each (loop, lane) gets its own SPSC queue and
  worker, which drops the shared-queue contention, and the FAST/SLOW
  lanes keep short crypto tasks off the long blocking ones (zone
  dump/load, xfrin). isc_work jobs are now cancelable: isc_work_cancel()
  tombstones a still-queued job and its after_cb fires with
  ISC_R_CANCELED, so abandoned work can be dropped instead of run to
  completion. :gl:`!12226`

- Simplify and modernize the radix tree implementation. ``5e6018bf7ab``

  Refactor the radix tree used for ACL IP prefix matching, originally
  imported from the MRT routing toolkit in 1999 and never modernized.
  Node size drops from 100+ bytes across two allocations to 64 bytes in
  a single cache line. Expand the unit test suite. :gl:`!11731`

- Simplify the delegation database memory management. ``80496aeb680``

  This is an internal simplification of the delegation database's memory
  management, replacing the per-thread eviction lists and deferred,
  cross-thread record cleanup with a single shared eviction list and
  immediate cleanup. There is no change to how delegations are cached or
  resolved. :gl:`!12181`

- Support larger DNSSEC keys and signatures. ``eed44c38762``

  Some DNSSEC tools and trust-anchor handling could fail when working
  with unusually large DNSSEC keys or signatures, including those used
  by post-quantum algorithms. These paths now accept DNSKEY, CDNSKEY,
  CDS, and RRSIG data up to the DNS record size limits, so large key
  material can be parsed, written, checked, and signed consistently.
  :gl:`!12370`

- Sync picohttpparser.c with upstream commit a875a01. ``0b13a184fc7``

  Synced with the h2o/picohttpparser upstream repository up to commit
  f4d94b48b31e0abae029ebeafcfd9ca0680ede58.

  This commit is just hygiene and consistency by keeping the vendored
  copy current. :gl:`!12159`

- Use SIEVE for TSIG generated-key LRU. ``1d6b19549c0``

  Replace the list-based LRU for TSIG KEYs with SIEVE-based LRU.
  :gl:`!12043`

- Use a single allocation per delegation database entry. ``68d58962586``

  The node and its zone-cut name are now stored in one variable-sized
  allocation instead of two. :gl:`!12187`

Bug Fixes
~~~~~~~~~

- Fix recursion loop in case of badly behaving forwarders.
  ``f52fe46dec8``

  When forwarding DNS queries, the CD bit is cleared on the first query,
  and the CD bit is only used as a fallback if the first query fails.
  However, due to a logic bug this could lead to an unbounded loop
  re-sending the same message, until the maximum query count is hit.
  This has been fixed. :gl:`#5804` :gl:`!12133`

- Fix a bug in DNS UPDATE processing with inline-signing enabled.
  ``fb47b6bf3ec``

  In rare cases the :iscman:`named` process could terminate unexpectedly
  when processing authorized DNS UPDATE messages in quick procession
  which are updating a zone with inline-signing enabled. This has been
  fixed. :gl:`#5816` :gl:`!11982`

- Fold receive_secure_serial into zone maintainance. ``58c570e5186``

  Having two separate zone maintainance async jobs increases the risk of
  race conditions. This commit folds the inline-signing resigning job
  into the zone maintainance of the secure zone, ensuring only one async
  job acts on a zone. :gl:`#5816` :gl:`!12005`

- Properly detect private records before copying. ``b378071e061``

  We were triggering an assertion when trying to copy a private record
  to a buffer for modifying.  Extend the private type detection and copy
  the contents after we have rejected invalid private records.
  :gl:`#5857` :gl:`!11816`

- Tighten  referral DS acceptance. ``aa8a07991d9``

  Named was accepting DS records for sibling zones when it shouldn't
  have.  This has been fixed. :gl:`#5870` :gl:`!11837`

- Don't synthesize negative responses with pending NSEC. ``10b8edb27f5``

  If an NSEC record has not yet been validated and is cached with trust
  pending, don't use it to synthesize negative responses. :gl:`#5872`
  :gl:`#5887`  :gl:`#5977` :gl:`!12281`

- Check that an NSEC signer is at or above the name to be validated.
  ``89e57b45e02``

  Add a check that an NSEC record being used as a proof of nonexistence
  for a given name is not signed by a name lower in the DNS hierarchy
  than the one in question. :gl:`#5876` :gl:`!12272`

- Don't evict DNSSEC-validated cache data on a CD=1 NXDOMAIN.
  ``84556763a48``

  When a client sent a query with the checking-disabled (CD) bit set and
  the answer was NXDOMAIN, the resolver cached that unvalidated negative
  response and discarded any DNSSEC-validated records it already held
  for the same name, even though the validated data was more
  trustworthy. A single such response - including a forged one - could
  flush validated records from the cache and force the resolver to fetch
  them again. The resolver now checks the trust level of the existing
  data first and leaves the cache unchanged when it is already
  validated. :gl:`#5877` :gl:`!11946`

- Fix a 'deny-answer-aliases' configuration bypass issue.
  ``50dbab93404``

  It was possible to use a maliciously crafted authoritative zone to
  make :iscman:`named` resolver synthesize a ``DNAME`` "alias" that
  should have been rejected by the configured :any:`deny-answer-aliases`
  option. This has been fixed. :gl:`#5930` :gl:`!12044`

- Reject external referrals from forwarders. ``a75146cdbac``

  Under `forward-first` policy in a forwarding zone BIND could accept NS
  above the forward zone apex from negative responses. This has been
  fixed.

  ISC would like to thank Qifan Zhang, of Palo Alto Networks, for the
  report. :gl:`#5937` :gl:`!12154`

- Fix a zone transfer over TLS (XoT) issue when using the opportunistic
  TLS mode. ``e0d84f8370e``

  The :iscman:`named` process, running as secondary DNS server,
  configured to transfer a zone from a primary server using an encrypted
  XoT transport in opportunistic TLS mode (i.e. without peer
  certificate/hostname validation) could terminate unexpectedly when the
  TLS ALPN negotiation with primary server was unsuccessful. This has
  been fixed. :gl:`#5957` :gl:`!12081`

- Unvalidated opt-out NSEC3 could be accepted in insecurity proof.
  ``d2350fc546a``

  When determining whether an insecure delegation is legitimate, NSEC3
  opt-out records which had not yet passed validation could be used.
  This has been fixed. :gl:`#5970` :gl:`!12283`

- Check wildcard signer and NOQNAME signer match. ``c5c68c1e952``

  A positive wildcard answer, and the NSEC3 proof that the requested
  name doesn't exist in the zone, must both be from the same zone.
  Otherwise, an NSEC3 from an ancestor zone could be used to interfere
  with validation.

  We now retrieve the signer name from a wildcard response's signature.
  An NSEC3 record cannot be used as a NOQNAME proof for the wildcard
  unless it exactly matches the name one level above the NSEC3.
  :gl:`#5971` :gl:`!12256`

- Check dns_rdata_fromstruct() return values. ``a957a241a45``

  In some functions implementing RFC 5011 key maintenance, the results
  of `dns_rdata_fromstruct()` were not checked. This has been fixed.
  :gl:`#5982` :gl:`!12017`

- Fix CNAME resolution failure caused by a cached SERVFAIL response.
  ``e0e1208dbb1``

  Under certain circumstances, a cached SERVFAIL response could
  incorrectly prevent successful resolution of a CNAME target. This
  could cause resolution failures to persist until the cached SERVFAIL
  entry expired, even when the CNAME target itself was otherwise
  resolvable. This issue has been fixed. :gl:`#5983` :gl:`!12158`

- [CVE-2026-13204] Prevent crash from malformed NSEC/NSEC3 response.
  ``b0d6639182f``

  An assertion could be triggered by an improperly signed NOQNAME proof.
  This has been fixed.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5985`

- Reject unsupported RSA DNSKEY shapes during DNSSEC validation.
  ``c7a0a6af4da``

  An authoritative server publishing an RSA DNSKEY with an unusually
  large modulus or an exotic public exponent could make each DNSSEC
  signature check on a validating recursive resolver noticeably more
  expensive than for a normally sized key.  Such DNSKEYs are now treated
  as invalid. :gl:`#6008` :gl:`!12054`

- Fix a bug in GeoIP2 string matching. ``242d931956b``

  When using GeoIP2 ACLs (see :any:`acl`), :iscman:`named` could
  incorrectly match a name using a sub-string instead of the full name
  match. This has been fixed. :gl:`#6019` :gl:`!12092`

- Fix DNS-over-HTTPS (DoH) quota configuration issue. ``476fdc53659``

  The :any:`http-listener-clients` and
  :any:`http-streams-per-connection` configuration options could be
  truncated to smaller values (or to ``0``, which means unlimited) when
  very big configuration values were used, which exceeded ``65535``. As
  a note - it is very unlikely that such big values are used in
  production, and the default values for the affected options are
  ``300`` and ``100``, correspondingly. This has been fixed. :gl:`#6021`
  :gl:`!12085`

- Fix invalid pointer release in JSON statistics-channel response.
  ``e18cbe6c5d3``

  Each response served on a JSON statistics endpoint released the wrong
  pointer to the JSON library after the response was sent: the response
  body string instead of the JSON document.  With the current responses
  this does not crash named in practice, but the call is incorrect and
  can in principle corrupt memory.  XML responses are not affected.
  :gl:`#6024` :gl:`!12068`

- Truncated reply to a TSIG query no longer stalls the resolver.
  ``19c202d470c``

  When an upstream server returned a truncated reply to a query that
  BIND had signed with TSIG, the resolver could keep waiting for a
  follow-up UDP packet that never arrived, so the query stalled until it
  hit resolver-query-timeout and the client received no answer. BIND now
  treats any reply it cannot authenticate as an immediate failure and
  returns SERVFAIL right away as a defense in depth. :gl:`#6028`
  :gl:`!12080`

- Keep RRL ncache fixed name alive. ``074efb57680``

  Move the fixed name storage out of the NCACHE branch so the name
  passed to dns_rrl() remains valid for cached NXDOMAIN responses.
  :gl:`#6029` :gl:`!12096`

- Ignore updates removing DNSKEY RRset with class ANY. ``e62fb7cb1be``

  When a Dynamic Update is received that removes the ``DNSKEY`` (or
  ``CDNSKEY``, or ``CDS``) RRset, remove all records except the ones
  that are in use for signing for the zone. :gl:`#6045` :gl:`!12166`

- Fix a memory leak when updating a zone with more than 32 DNSSEC keys.
  ``1b8bae505e7``

  Applying changes to a signed zone — via DNS UPDATE or the
  inline-signing raw-to-secure sync — leaked the surplus keys when the
  zone's key directory held more than 32, slowly growing named's memory
  use. :gl:`#6051` :gl:`!12328`

- Fix the memory ordering in the adaptive read-write lock.
  ``b2ad41d3e71``

  On hardware with a weak memory model, the internal read-write lock
  could briefly admit a reader and a writer at the same time, risking
  sporadic crashes or incorrect data. The reader/writer handshake now
  uses sequentially consistent ordering so the two can no longer
  overlap. :gl:`#6060` :gl:`!12162`

- Print the full OID in PRIVATEOID key comments. ``c3fe58093d9``

  The OID in the "; alg = ..." comment of a PRIVATEOID key was truncated
  to sixteen characters. :gl:`#6092` :gl:`!12377`

- Correct locator decoding for NID, L64, and L32 records.
  ``f5e5097fad2``

  NID, L64, and L32 records were decoded incorrectly when converted into
  their parsed structures, because the preference field was not skipped
  before the locator. :gl:`#6097` :gl:`!12348`

- Do not assert on synthrecord reverse mode with huge prefix.
  ``fe8f3d9e814``

  When using the `synthrecord` plugin in reverse mode, if a very long
  prefix is configured by the operator such that there is no room to fit
  the reversed IP address into a DNS name, `named` could assert. This
  has now been fixed. In such situations, an error is logged so the
  operator is aware of the problem, and `NXDOMAIN` is answered.
  :gl:`#6115` :gl:`!12173`

- Fix a possible crash when cleaning up a view's caches. ``af661f06d02``

  In rare cases named could crash while a view was being removed, for
  example during reconfiguration or shutdown, as its internal caches
  were torn down. This has been fixed. :gl:`#6119` :gl:`!12177`

- Validate query and response time nanosecs when parsing dnstap.
  ``b362e0b30d6``

  An assertion is triggered inside `isc_time_set` when dnstap-read calls
  `dns_dt_parse` on dnstap files with query/response time nanosecond
  fields greater than a second.

  Avoid the assertion by validating the nanosecond fields to be
  subsecond when parsing. :gl:`#6123` :gl:`!12224`

- Fix delegdb dump buffer overflow. ``684f5774585``

  A buffer used to dump a DNS name in the delegdb dump flow was using
  the wrong size: it was using `DNS_NAME_MAXWIRE` which is the actual
  max length of a DNS name on the wire instead of using
  `DNS_NAME_FORMATSIZE` which is the maximum length of a textual
  representation of a DNS name (which can be way longer than
  `DNS_NAME_MAXWIRE` if using the master file escape sequence format)
  plus 1 (end of string byte). This could lead to a buffer overflow.
  This is now fixed. :gl:`#6132` :gl:`!12195`

- Preserve the request message across async SIG(0) processing.
  ``15689d69c6e``

  For SIG(0)-signed requests, view matching is offloaded and the request
  is finished asynchronously from ns_client_request_continue(), which
  passes client->inner.buffer to dns_dt_send().  That buffer aliases the
  network manager's receive buffer, only valid during the read callback,
  so it may already be freed and reused, producing garbage dnstap frames
  (e.g. the "upforwd" sig0-over-DoT test fails with UQ=0).

  Copy the request message when entering async mode and reference the
  copy, freeing it in ns__client_reset_cb().

  Assisted-by: Claude:claude-opus-4-8 :gl:`#6139` :gl:`!12189`

- Ignore 0-byte reads in the TCP read callback. ``d92030f7b20``

  Callbacks for libuv stream reads do not signal zero-length reads as a
  failure signal but rather as EAGAIN/EWOULDBLOCK. This can trigger an
  assertion when a zero-length read is pushed onto a PROXYv2 endpoint
  that has not yet processed the headers as it expects a non-NULL region
  of positive length. :gl:`#6140` :gl:`!12261`

- Fix PROXYv2 header size truncation bug. ``ee5763880ac``

  The 'isc_proxy2_handler_t' structure stores some size values in a
  'uint16_t' type, while the maximum size can be bigger, which results
  in truncation. Change the affected types to 'size_t'. :gl:`#6142`
  :gl:`!12294`

- Include the IPv6 address's brackets in the parsed URL/URI host.
  ``06413e57673``

  The brackets are not included in the host component of the parsed
  URL/URI. Change the parser to include the brackets. :gl:`#6147`
  :gl:`!12266`

- Improve the input validation of the isc_url_parse() function.
  ``d960de55be6``

  The isc_url_parse() function failed to check the input buffer's length
  and assumed that it can't be bigger than UINT16_MAX, because both the
  'off' and 'len' fields of the 'isc_url_parser_t' structure are
  uint16_t.

  Add a check to not accept a buffer longer than 8192 octets.
  :gl:`#6150` :gl:`!12252`

- Detect UTF-16 surrogates in `isc_utf8_valid()` ``dfefde8481a``

  UTF-8 standard forbid usage of unicode character between the range of
  0xD800..0xDFFF (reserved, and used as UTF-16 surrogates, see RFC
  3629).

  However, `usc_utf8_valid()` was not checking if the encoded unicode
  character was in this range, which then would accept invalid UTF-8
  strings. This is now fixed. :gl:`#6151` :gl:`!12345`

- Only print per zone glue stats when query statistics is full.
  ``2b3911290f3``

  The code printing query statistics was ignoring the zone-statistics
  option. This has been fixed. :gl:`#6164` :gl:`!12262`

- Remove dead code warnings found by scan-build. ``9155946be89``

  Small cleanup, fixing the dead code issues found by scan-build.

  Patch submitted by Tim Rühsen. :gl:`#6165` :gl:`!12293`

- CDS/CDNSKEY records were not removed when re-configuring the server.
  ``68565cd6fe8``

  When on an ``rndc reconfig`` the DNSSEC policy changes such that it
  changes the expected ``CDNSKEY`` and/or ``CDS`` records in the zone,
  the RRset should be updated accordingly. This did not happen when
  removing digests from the configuration, or setting `cdnskey no;`.
  This has been fixed. :gl:`#6166` :gl:`!12265`

- Stop reusing outgoing TCP connections the peer has already closed.
  ``1541662c658``

  ``named`` could hand a new query an idle forwarder/upstream TCP or TLS
  connection that the peer had already closed, causing the query to fail
  (and CLOSE-WAIT sockets to pile up). Idle reused connections are now
  watched, so a close is noticed and the connection is dropped instead
  of reused. A new ``tcp-reuse-timeout`` option controls how long an
  idle outgoing connection is kept open for reuse (default 5 seconds).
  :gl:`#6171` :gl:`!12289`

- Fix DNSSEC validation failures for names under an apex DNAME.
  ``aefb8570a2a``

  DNSSEC validation could fail with SERVFAIL for names covered by a
  DNAME at the apex of a signed zone, unless the zone's keys were
  already validated in the cache. This regression was introduced by the
  recent fix for resolver stalls on CNAME responses to DS queries.
  :gl:`#6176` :gl:`!12353`

- Fix a crash when resolving names below a cached DNAME. ``bec027557db``

  A recursive resolver could crash when it answered a query for a name
  beneath a cached DNAME while that same DNAME record was concurrently
  refreshed or evicted from the cache. :gl:`#6182` :gl:`!12337`

- Resolver could terminate unexpectedly when processing a malformed
  RRSIG. ``03c495def67``

  A recursive resolver could terminate unexpectedly when an
  authoritative server returned a crafted RRSIG(RRSIG) record for an
  insecure zone. Such records are now rejected. :gl:`#6184` :gl:`!12347`

- Assorted Meson fixes. ``f27acdfd5a9``

  :gl:`!12167`

- Avoid needless queries when the DNSSEC validation limit is reached.
  ``2777ef5d67d``

  A validating resolver could send one needless upstream query after
  reaching its per-fetch DNSSEC validation limit. It now stops
  immediately.

- Avoid writing through a const pointer in render_xsl() ``7d20711c651``

  render_xsl() served the static XSL stylesheet by casting away the
  const qualifier of xslmsg and handing the pointer to
  isc_buffer_reinit():

  p = UNCONST(xslmsg);     isc_buffer_reinit(b, p, strlen(xslmsg));

  isc_buffer_reinit() copies any pre-existing buffer content into the
  new base with memmove(), so the call would write into xslmsg, which is
  a 'const char[]' living in read-only memory.  This is safe today only
  because the supplied bodybuffer is always freshly initialized with
  length 0, so the memmove() never runs -- a fragile,
  action-at-a-distance invariant that GCC's -fanalyzer flags as a write
  to a const object (-Wanalyzer-write-to-const).

  Use isc_buffer_constinit(), the primitive intended for pointing a
  buffer at constant data: it goes through isc_buffer_init() and never
  writes to the base.  This drops the UNCONST cast, keeps xslmsg in
  read-only memory, and silences the analyzer warning.

  Assisted-by: Claude:claude-opus-4-8 :gl:`!12168`

- Build the fuzzers without the libbindtest test library.
  ``c8e98231213``

  Every fuzz target depended on libtest_dep, which forces building the
  libbindtest shared library.  In a static build (as used by OSS-Fuzz)
  that link fails: libbindtest's netmgr wrappers multiply-define symbols
  that also live in the static libisc/libns archives, and the static
  system libraries are not position independent.

  Only fuzz_dns_qp actually uses the qp test helpers, so give it just
  tests/libtest/qp.c via the new libtest_qp_dep and drop libtest_dep
  from the fuzzers.

  Assisted-by: Claude:claude-opus-4-8 :gl:`!12194`

- Cache glue only for enabled address families. ``e0a74bf3cbd``

  When caching delegation NS data, only use A/AAAA glue records if the
  resolver has the corresponding IPv4/IPv6 dispatcher configured. If
  IPv4 or IPv6 is disabled, ignore glue for that family and fall back to
  caching the nameserver name if there is no glue from the other
  supported family. :gl:`!11889`

- Don't serve a stale CNAME or record when fresh data of the other
  exists. ``ac6696cdb52``

  When a cached name held both a CNAME and records of another type — one
  stale, the other still fresh — named with serve-stale could return the
  expired set instead of the fresh one, in either direction. It now
  prefers whichever is fresh. :gl:`!12282`

- Only update the global tid_count once. ``096479cc19b``

  Skip updating the `tid_count` value on repeated calls to prevent
  ThreadSanitizer 'data race'. :gl:`!12186`

- Remove ACL detach deadcode from dyndb. ``094efe68e35``

  Since `188aa43e`, `dns_acl_any()` can't fail (and thus would always
  set memory to its target). Removing deadcode that would detach the ACL
  if `dns_acl_any()` would return some error while the ACL would be
  created and attached. :gl:`!12333`

- Update dnssec validation test to match new behavior. ``8c482ae8b0c``

  Some of the tests in `dnssec/tests_validation.py` worked by iterating
  through the response message looking for failure conditions, such as
  excessively high TTL values. In some cases, previous changes caused
  additional data not to be returned. Since there was nothing to
  iterate, the tests still "passed".      Tests that don't make sense
  anymore have been removed. Other tests that iterate through responses
  have been updated with checks to ensure that the responses actually do
  contain data. :gl:`!12269`


