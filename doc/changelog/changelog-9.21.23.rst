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

BIND 9.21.23
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix DNS64 owner case after DNAME restart. ``2efeb361d9``

  When BIND 9 is configured to use DNS64 and encounters a DNAME
  redirect, it could end up using freed memory for the DNS response
  owner name. This caused the response to contain corrupted data. This
  fix ensures the correct owner name is used when constructing the
  synthesized response after a DNAME redirect.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5934`

New Features
~~~~~~~~~~~~

- Enable PR-Agent reviews on merge requests. ``9755fb6455``

  Adds a CI job that runs PR-Agent against each merge request opened
  from the canonical repository, posting an automated review and
  code-improvement suggestions as MR comments. The job is gated to
  same-project source branches so the OpenAI key and personal access
  token are not exposed to fork pipelines. :gl:`!12032`

Removed Features
~~~~~~~~~~~~~~~~

- Remove legacy special handling for SIG, NXT, and KEY records.
  ``ac342bf652``

  BIND no longer applies legacy RFC 2535 handling to the obsolete
  ``SIG``, ``NXT`` and ``KEY`` record types; they are now served as
  plain zone data. Zones with both a ``CNAME`` and a ``KEY`` and or
  ``NXT`` at the same name — invalid under :rfc:`2181` — will now fail
  to load and must be corrected. :gl:`#6007` :gl:`!12056`

- Remove useless PR-Agent jobs. ``d61fef7c10``

  The experiment was a failure, the PR-Agent doesn't send a full context
  to the AI Agents and the results are abysmal because of that.
  :gl:`!12119`

Feature Changes
~~~~~~~~~~~~~~~

- Fall back to TCP on a UDP response with a mismatched query id.
  ``ef405bfa6d``

  BIND used to wait silently for the correct DNS message id on a UDP
  fetch even after receiving a response from the expected server with
  the wrong id, leaving room for off-path spoofing attempts to keep
  guessing within that window.  The resolver now retries the fetch over
  TCP on the first such response, and a new MismatchTCP statistics
  counter tracks how often the fallback fires. :gl:`#5449` :gl:`!12023`

- Cap glue records cached from a referral. ``8c4e7d533e``

  named cached every glue record from a referral, retaining far more
  than resolution will ever use.  The number of nameservers and
  addresses kept per referral is now bounded in the delegation database.
  :gl:`#5701` :gl:`!11970`

- Fix a resolver stall on a CNAME response to a DS query. ``ed3a16bea8``

  A validating resolver could stall for about twelve seconds and then
  return SERVFAIL when an authoritative server answered a DS query with
  a CNAME. Such responses are now rejected promptly, so the query fails
  fast instead of hanging. :gl:`#5878` :gl:`!11867`

- Named could crash on concurrent TKEY DELETE for the same key.
  ``54f5210463``

  On a server configured with tkey-gssapi-keytab (or
  tkey-gssapi-credential), an authenticated peer could crash named by
  sending two TKEY DELETE requests for the same dynamic key in rapid
  succession.  This has been fixed. :gl:`#6001` :gl:`!12041`

- Allow any valid DNS name as a TSIG/RNDC key name. ``fce9f32367``

  The key-generation tools (tsig-keygen, rndc-confgen) now accept any
  valid DNS name for key names. :gl:`!12029`

- Consolidate the validator's DS fetches into one helper. ``4ff4e1346e``

  Internal cleanup with no change in resolution behaviour. The DNSSEC
  validator started DS record lookups from three separate places, each
  set up slightly differently; they now go through a single helper.
  :gl:`!12144`

- Make dns_glue_t private to qpzone. ``f65c5b0ab6``

  The dns_glue struct currently contains four dns_rdataset structs to
  hold the glue. These structs are over 100 bytes each because they need
  to be able to hold data for multiple types of databases.

  Since the dns_glue_t type is only used by qpzone, we can instead hold
  pointers to the vecheaders directly, and only bind the vecheaders to
  the rdatasets when adding the glue to the message.

  This leads to a 33% memory reduction in some authoritative benchmarks.
  :gl:`!11801`

- Skip in-domain nameservers that have no glue. ``c7b53348fc``

  A referral that names a nameserver inside the delegated zone but
  provides no address for it leaves the resolver unable to reach that
  server. named now logs "missing mandatory glue for <name>" at notice
  level and skips the nameserver. :gl:`!11971`

- Use SipHash-1-3 for hash tables, keep SipHash-2-4 for cookies.
  ``c708d694fe``

  SipHash-2-4 was designed as a conservative PRF/MAC with extra rounds
  against future attacks.  For hash tables, where outputs are never
  exposed, SipHash-1-3 provides sufficient collision resistance with
  fewer rounds.  As the SipHash author noted: "I would be very surprised
  if SipHash-1-3 introduced weaknesses for hash tables."

  DNS cookies continue to use SipHash-2-4 since cookie values are sent
  on the wire and must resist online attacks. :gl:`!11787`

Bug Fixes
~~~~~~~~~

- The resolver now removes other RRsets at the same name when caching a
  CNAME. ``9f84037814``

  When an RRset is in stale cache, and the authoritative server changes
  the record type to CNAME, the resolver fails to refresh the stale
  cache. This has been fixed. :gl:`#5302` :gl:`!11758`

- Fix TCP fallback after repeated UDP timeouts. ``e90a828307``

  When an authoritative server failed to respond to two consecutive UDP
  queries in a fetch, named was supposed to retry the next attempt over
  TCP but in fact still sent it over UDP.  The resolver now properly
  switches the transport to TCP on the third attempt to the same server.
  :gl:`#5529` :gl:`!12022`

- Enable Edwards curves with PKCS#11. ``ebb4e5e5b7``

  Ed25519 and Ed448 curves did not work in PKCS#11. This has been fixed.
  :gl:`#5762` :gl:`!11591`

- Fix nxdomain-redirect combined with dns64. ``be4f6ad202``

  When a resolver was configured with both `nxdomain-redirect` and
  `dns64` in the same view, an AAAA query for a nonexistent name could
  abort `named`. The combination failed whenever the redirect zone held
  A records but no AAAA records.  The server now serves the empty AAAA
  response from the redirect zone as-is, instead of attempting DNS64
  synthesis on top of it. :gl:`#5789` :gl:`!12059`

- Clear REDIRECT flag when it isn't needed. ``222d86fee8``

  When `nxdomain-redirect` is in use, and a recursive query is used to
  get the redirected answer, a flag is set to distinguish it from a
  normal recursive response. Previously, that flag was left set
  afterward, which could trigger an assertion if a normal recursive
  query was sent later on behalf of the same client: for example,
  because the `filter-aaaa` plugin was in use.  This has been fixed.
  :gl:`#5936` :gl:`!12073`

- Fix data race during rndc dumpdb or zone load. ``29f0b07e8c``

  'rndc dumpdb' against a server with zones, and async zone load, had a
  timing window where the operation's completion could fire before the
  server had finished registering the operation, occasionally leading to
  a possible crash.  The completion is now delivered after the
  registration is in place. :gl:`#5952` :gl:`!11991`

- Bound memory use during incoming zone transfers. ``d524dec8b0``

  During an incoming zone transfer, an optimization could let the batch
  of pending records grow without bound for a large zone, raising memory
  usage. It gave no measurable performance benefit, so it has been
  removed. :gl:`#5958` :gl:`!12141`

- Disable output escaping in bind9.xsl. ``2091d703ac``

  The statistics charts where not displaying on some browsers. This has
  been fixed. :gl:`#5990` :gl:`!12018`

- Fix crash on badly configured secondary signer. ``a97e5c3031``

  A badly configured secondary signer that was missing the 'file' entry
  caused the server to crash, rather than to reject the configuration.
  This has been fixed. :gl:`#5993` :gl:`!12045`

- Fix possible NULL dereference in `cfg_map_findclause()` ``d312d16bfd``

  `cfg_map_findclause()` did not check whether a clause existed before
  dereferencing it, which could lead to a NULL dereference. Add the
  missing check to prevent this.

  In practice, this was not triggering any known bug, since
  `cfg_map_findclause()` is only called in contexts where the clause is
  known to exist. :gl:`#5997` :gl:`!12052`

- Reject RRSIG records covering meta-types. ``78ececa6bd``

  A recursive resolver could accept and cache an RRSIG record whose
  Type-Covered field names a meta-type (ANY, AXFR, IXFR, MAILA, MAILB),
  even though no real RRset of those types ever exists. Such records are
  now rejected by the DNS message parser. :gl:`#6002` :gl:`!12048`

- Validate nsec3hash arguments instead of relying on atoi()
  ``3931490291``

  The nsec3hash tool parsed its algorithm, flags, and iterations
  arguments with atoi(), then range-checked the result. For values that
  overflow int during digit-by-digit accumulation, atoi() is undefined;
  in practice on musl libc the modular wrap leaves n == 0, which
  silently passes the "iterations > 0xffffU" check. On Alpine Linux this
  made nsec3hash succeed with iterations treated as 0 for inputs like
  4294967296 (2^32).

  The latent bug only surfaced when the recent image rebuild pulled in
  Hypothesis 6.152.9 (2026-05-19), which unified the distribution used
  for bounded and unbounded integers() strategies. The new smoother
  distribution explores the 2^32 boundary on unbounded ranges like
  integers(min_value=65536); earlier versions did not reach there, so
  test_nsec3hash_too_many_iterations only started failing on Alpine
  after the image refresh.

  Replace the three atoi() calls with isc_parse_uint8 /
  isc_parse_uint16, which uniformly reject overflow, trailing garbage,
  leading sign, and non-numeric input across libc implementations. As a
  side effect, error messages now include the offending argument and a
  specific reason ("out of range" vs "not a valid number").

  Assisted-by: Claude:claude-opus-4-7 :gl:`#6013` :gl:`!12062`

- Configure zone ACLs from templates. ``5c80876a6d``

  ACLs from templates should be configured in between the zone and view
  tier. :gl:`#6023`  :gl:`#6040` :gl:`!12132`

- Check options in templates that must be non-zero. ``4f9422a27d``

  `named-checkconf` should reject a template that has options that must
  be non-zero (`max-refresh-time`, `max-retry-time`, `min-refresh-time`,
  `min-retry-time`).

  `rndc addzone` with a zone that refers to such template should fail
  cleanly. :gl:`#6041` :gl:`!12126`

- Fix stdc_count_zeros/stdc_count_ones polyfill mismatch. ``2226f19643``

  A previous commit introduced a latent bug where the wrong popcount
  definition was used when overriding the compilation mode to C23. This
  MR fixes it. :gl:`#6055` :gl:`!12165`

- Fix isc__tid_initcount() REQUIRE. ``137e3a5e57``

  `isc__tid_initcount()` was checking that the current number of thread
  didn't exceed `ISC_TID_MAX`, not the newly assigned number. This is
  now fixed. :gl:`#6113` :gl:`!12164`

- Don't remove corresponding RRSIG in the same loop. ``3b45b43600``

  The `dns_db_deleterdataset()` removing the corresponding signature
  within the iterator is wrong, because it mutates an rdataset that is
  not the current one.  This has been fixed. :gl:`!12047`

- Fix wrong variable in named_server_sync() log message. ``f8a222b1d8``

  named_server_sync() logged isc_result_totext(result) but returns
  tresult. The loop accumulates errors into tresult, so result only
  holds the last iteration's value. If the last view succeeded but an
  earlier one failed, the log would incorrectly say "success".
  :gl:`!12090`

- Move last_purge declaration under the same #ifdef as its user.
  ``86029384e2``

  The static atomic last_purge is only read and written from
  mem_purge(), which is compiled only when JEMALLOC_API_SUPPORTED or
  __GLIBC__ is defined. This used to fail on OpenBSD:

  ../lib/isc/mem.c:405:31: error: unused variable 'last_purge'
  [-Werror,-Wunused-variable]       405 | static _Atomic(isc_stdtime_t)
  last_purge = 0;           |                               ^~~~~~~~~~
  :gl:`!12058`

- Refine resolver fetch loop detection. ``b76790dd3c``

  The resolver's fetch loop detection now triggers only when a new fetch
  would join an already in-flight fetch that is also one of its own
  ancestors, which is the actual loop condition.  Previously the check
  ran against the original request before the fetch was set up.
  :gl:`!12145`

- Restore delegdb size after `rndc flush` ``71e8d16357``

  When the delegation database was flushed using `rndc flush`, its size
  was also reset but not restored. As a result, after `rndc flush` was
  used at least once, the delegation database size could grow unbounded.
  This has now been fixed. :gl:`!12101`

- Run PR-Agent only when manually triggered. ``be727bd5e2``

  :gl:`!12033`


