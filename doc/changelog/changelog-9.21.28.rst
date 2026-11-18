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

BIND 9.21.28
------------

New Features
~~~~~~~~~~~~

- Add configuration to set key flags SEP and ADT. ``0d9c7794c16``

  A new parameter to DNSSEC policy ``keys`` has been added to set the
  key flags SEP and/or ADT. :gl:`#6432` :gl:`!12923`

- Add CID and stateless reset token routing for QUIC. ``a3942d79a4a``

  QUIC is a protocol that is agnostic of the source address/port and
  uses connection IDs and stateless reset tokens to distinguish
  sessions.

  The thread-safe `isc_quic_router_t` structure keeps track of this
  information and also has functionality for inspecting packets to find
  the appropriate action alongside the associated connection if it
  exists. :gl:`!12359`

- Add support for the ML-DSA-44 post-quantum DNSSEC algorithm.
  ``52f9fb9b48c``

  BIND 9 can now generate keys, sign zones, and validate signatures
  using ML-DSA-44 (DNSSEC algorithm number 18), the post-quantum
  signature scheme specified in draft-westerbaan-dnssec-mldsa. The
  algorithm is available in dnssec-keygen, dnssec-signzone, and
  dnssec-policy when BIND 9 is built against OpenSSL 3.5 or newer.
  ML-DSA-44 public keys are about 1.3 KB and signatures about 2.4 KB, so
  signed responses are considerably larger than with the existing
  algorithms. :gl:`!12769`

- QUIC state machine. ``fcbce32b8e8``

  Add a thread-specific state machine for managing QUIC connections.

  The connection is driven by pulling outgoing packets and pushing
  incoming packets, stream control and stream data with peer events
  triggering via callbacks when pushing packets. :gl:`!12046`

- Support for authoritative DELEG. ``fc79a7496d5``

  Implement authoritative support for extensible DNS delegation records
  (DELEG), based on the draft in progress at
  https://ietf-wg-deleg.github.io/draft-ietf-deleg-base/draft-ietf-deleg.html.

  DELEG is assigned to type 61440, DELEGPARAM to 54.

  If a zone contains a DELEG referral, it will be used to answer clients
  if they signal their understanding of DELEG records by setting the DE
  (DELEG OK) flag in queries. `dig +deflag` (or `+de` for short) can be
  used to set the flag on queries.

  The DELEG specification relaxes the requirement that all zones must
  have an NS RRset at the apex, so this is no longer enforced by default
  in `named`. A new `check-ns` option has been added to `named.conf`
  which can be used to control this: the allowed values are `fail`,
  `warn` and `ignore`, and the default is `warn`. Missing NS records are
  also no longer fatal in `named-checkzone`, but `-n fail` will restore
  the old behavior.

  A new flag has been added to DNSKEY records: Authoritative Delegation
  Types (ADT). If this flag is set for any key in the DNSKEY RRset, it
  indicates to a validator that this server implements authoritative
  DELEG: if a referral response does not contain a DELEG record, it
  _will_ contain a cryptographic proof that the DELEG record does not
  exist. If no ADT-flagged keys are present when signing a zone that
  contains DELEG, a warning will be logged. Before any DELEG records are
  added to a zone, an ADT key should be added to the zone, and all
  authoritative servers for the zone must support DELEG.

  Note:  This branch does not implement recursive support for DELEG. The
  resolver does not set the DE flag when sending iterative queries, and
  DELEG-based referrals are not processed. This will be added in later
  work. :gl:`!10995`

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate NXDOMAIN redirection. ``5a9e485544d``

  The `nxdomain-redirect` option and `type redirect` zones are now
  deprecated. A warning will be generated when these are encountered in
  `named.conf`.

  Related to #6451 :gl:`!12930`

- Remove obsolete UDP response truncation fallback. ``0ba7d9946fc``

  Since UDP sockets were changed to allow fragmentation, responses
  limited by max-udp-size can no longer trigger the fallback that
  replaces a failed send with an empty truncated response. Remove this
  unreachable handling so UDP send failures follow the standard error
  path. :gl:`!12965`

- Remove the atomic_ptr() wrapper. ``84e2f4f93a6``

  The wrapper has a single user and saves nothing over spelling out
  `_Atomic(type *)`.  Coccinelle cannot parse its definition, so the
  header costs the semantic patches a few lines of coverage for no
  benefit.

  Assisted-by: Claude:claude-opus-5-5 coccinelle :gl:`!12881`

Feature Changes
~~~~~~~~~~~~~~~

- Replace stroul with custom implementation in isc_parse_*
  ``10d08754701``

  The isc_parse_* family of functions are also now expanded to 64-bit
  integers but they still use the `stroull`/`strtoll` internally with
  better checking and constraints.

  Furthermore, there is now a C11 generic version of the parseint
  functions.

  There is a current exception strtol calls for strings that doesn't
  contain only the number. :gl:`#5902` :gl:`!11935`

- Faster IXFR for inline-signed zones. ``c7fbdf5a8ea``

  Previously, the implementation of dns_diff_appendminimal could lead to
  quadratic complexity when used in a loop. We introduce an
  dns_diff_appendlistminimal method for diffs that uses an hashmap to
  minimize the diff, leading to linear complexity.

  ISC would like to thank Qifan Zhang, of Palo Alto Networks, for
  reporting this issue. :gl:`#5980` :gl:`!12185`

- Reduce rdatavec merge and subtract complexity. ``39bfe5898de``

  Previously certain operations were quadratic, now they use a "zip
  merge" algorithm that is linear. :gl:`#6336` :gl:`!12845`

- Dig +https now requires a SubjectAltName in the server certificate.
  ``c020ac8daf4``

  When verifying a DNS-over-HTTPS server's hostname, "dig +https"
  accepted a certificate whose only name was in the Subject Common Name,
  while "dig +tls" already required a SubjectAltName. Current TLS
  standards have retired the Common Name, and OpenSSL 4.1 no longer
  consults it, so the same certificate was accepted or rejected
  depending on the OpenSSL version. Both transports now match the
  hostname against the SubjectAltName only, so a DoH server certificate
  without one is rejected with a peer verification failure. named is not
  affected, as its outgoing TLS connections already enforced this.
  :gl:`!12942`

- Intern configuration clause strings. ``fed1084bfe5``

  Configurations with a huge amount of zones lead to big abstract syntax
  trees composed mostly of string->cfg_obj_t maps, where the strings
  come from a known subset. With this change, we replace the string keys
  with indices in a string table. This substantially speeds up hashing,
  and therefore startup and rndc reconfig. :gl:`!12921`

- Linear time zone options check. ``2f943b45877``

  Make the check of zone options validity linear in the number of zone
  options + zone template options present. :gl:`!13034`

- Minimize ANY responses over TCP when minimal-any is enabled.
  ``50522ba048c``

  When :namedconf:ref:`minimal-any` was enabled, BIND minimized ANY
  responses over UDP but returned all available RRsets over TCP. BIND
  now returns a single RRset, with its covering RRSIGs when requested,
  and omits unnecessary authority and additional data regardless of
  transport. :gl:`!12581`

- Reduce per-zone memory overhead. ``4f8a0ff486a``

  This MR reduces the overhead of each zone by around 1kb by reducing
  the size of `dns_zone_t`. :gl:`!12829`

- Remove bracketed text. ``7051e05e6fa``

  This commit removes the bracketedtext lexer token type, and replaces
  it with a list of strings. The bracketedtext option made the grammar
  substantially more complex and made several parser optimizations
  impossible.

  The new bracketed tokens category is slightly more restrictive, as it
  doesn't distinguish quoted and unquoted text, does not allow bare
  escaped strings and limits the use of include within a plugin stanza.
  :gl:`!12920`

- Simplify RDATA wire serialization. ``7608cad9cb9``

  Move the _towire functions to a single file, and replace the generated
  RDATA_TOWIRE switch with an hardcoded one. This will allow further
  refactoring down the road. :gl:`!12704`

- Split dns_name_t into two types. ``fbbe52ea6d0``

  The dns_name_t type is widely used through the codebase. It also
  occupies 64 bytes, which is a substantial overhead given that domain
  names are usually smaller than 32 bytes.

  Most of the overhead comes from the two intrusive linked lists and the
  hashmap pointer embedded in the type. Those intrusive linked lists are
  only used in a fraction of the cases.

  This commit splits dns_name_t into two types, one which contains the
  linked lists, and one that doesn't, and uses the former only when the
  linked lists are necessary. :gl:`!11776`

- Using NSEC3 salt is deprecated. ``580020bcae9``

  BCP 236 recommends not using salt and iterations. We have been
  disallowing extra iterations for a while now, we will now also
  deprecate salt. :gl:`!12755`

Bug Fixes
~~~~~~~~~

- Fix possible performance issue when issuing rndc commands very
  frequently. ``bdaa622c6d2``

  The :iscman:`rndc` command could get slow if large number of requests
  was made over a short period of time. This has been fixed. :gl:`#3698`
  :gl:`!12918`

- Replace SoftHSMv2 with Kryoptic in the PKCS#11 system tests.
  ``606435b3359``

  SoftHSMv2 made the enginepkcs11 and keyfromlabel system tests fail at
  random: key generation through pkcs11-provider returned
  CKR_GENERAL_ERROR when named created keys for many zones at once,
  after which named backed off for ten minutes. The tests now use
  Kryoptic as the software token, selected with the
  BIND9_TEST_KRYOPTIC_MODULE environment variable, and render their own
  OpenSSL and Kryoptic configuration, so OPENSSL_CONF and SOFTHSM2_CONF
  no longer have to be set to run them. PKCS#11 labels for key-store
  keys may now be as long as a private key file field, so a pin-source
  with an absolute path no longer makes key generation fail with "ran
  out of space". :gl:`#4695` :gl:`!12827`

- Fix Offline KSK signing when the KSK and a ZSK share a key tag.
  ``11d3a372027``

  With dnssec-policy offline-ksk, the KSK and the ZSKs are generated
  separately, so a ZSK can have the same key tag as the KSK. named then
  mistook the ZSK for the KSK when signing the zone: the DNSKEY RRset
  was left without the KSK signature from the imported SKR, or,
  depending on the signing algorithm, importing the SKR failed with a
  "not exact" error. This has been fixed. :gl:`#5540` :gl:`!12893`

- Omit pending data from type-ANY cache responses. ``0c5c855d0be``

  When answering a type-ANY query from the cache, data that hasn't been
  validated yet should only be included in the response if the query has
  the CD bit set. :gl:`#5984` :gl:`!12896`

- Rndc accepts stale or mismatched signed responses. ``a7ca2466e99``

  The :iscman:`rndc` command could accept reflected requests as answers.
  Additionally, replayed responses could be accepted. This has been
  fixed. :gl:`#6101` :gl:`!12849`

- Make "rndc -r" work when "rndc" and "named" are from different builds.
  ``5095898f51d``

  Previously :option:`rndc -r` was only guaranteed to display the right
  value when rndc and named were from the same build.  This has been
  fixed. :gl:`#6102` :gl:`!12397`

- DoH client Content-Type validation accepted invalid values.
  ``12d28b25357``

  The Content-Type validation accepted any value that started with
  `application/dns-message`.  This has been fixed. :gl:`#6137`
  :gl:`!12851`

- Prevent a crash when using synthrecord. ``7b746fcb5b3``

  An assertion failure could occur when using the `synthrecord` plugin,
  in conjunction with a truncated answer to a client. This is now fixed.
  :gl:`#6185` :gl:`!12350`

- Send TSIG when NOTIFY is retried over TCP. ``b3791fc4339``

  NOTIFY messages were not TSIG-signed when retried over TCP. This has
  been fixed. :gl:`#6240` :gl:`!12947`

- Try the next server instead of aborting the zone transfer.
  ``7a40a82df92``

  In some cases of a misconfigured primary server, for example, when it
  returned a zone with too many records or a zone that failed
  verification, the zone transfer could get aborted altogether on the
  secondary server instead of trying the next configured primary. This
  has been fixed. :gl:`#6352` :gl:`!13009`

- Automatic interface scanning could stop after a burst of address
  changes. ``934834397ab``

  When many addresses were removed and added again in quick succession,
  as happens with "netplan apply", the kernel could drop some of the
  resulting interface change notifications. named then gave up on
  automatic interface scanning, logging "automatic interface scanning
  terminated: not enough free resources", and stopped listening on some
  addresses until it was restarted. Lost notifications now trigger a
  fresh scan of the interfaces once the burst is over, and named asks
  the kernel to report only address changes and to queue more of them,
  so that notifications are lost less often in the first place.
  :gl:`#6389` :gl:`!12705`

- Do not link zones into the zonemgr. ``46190e735b9``

  Previously zones were part of a linked list owned by the zonemgr that
  was used to print statistics. This MR instead walks the view list and
  the zone table for each view.

  As a side effect, it also makes the zonemgr explicitely a global
  singleton. Previously, only one instance existed but it was reference
  counted. :gl:`#6401` :gl:`!12858`

- Don't downcase the QNAME in synthrecord. ``acf055317a1``

  The synthrecord plugin had an unwanted side-effect of overwriting the
  query name for a query with a lower-case copy of itself, meaning a
  response could be returned that does not match bit-for-bit with the
  question sent. This has been corrected. :gl:`#6403` :gl:`!12946`

- DS queries for CNAME names were fetched upstream on every query.
  ``5b7e1dd0f33``

  A resolver answering a DS query for a name that is a CNAME (for
  example www.example.com pointing to example.com) ignored the CNAME it
  had already cached and sent the query upstream every time, so such
  answers were never served from the cache. The cached CNAME is now used
  for DS queries as for any other type, while a DS record or a negative
  DS answer cached at the same name still takes precedence. :gl:`#6455`
  :gl:`!12925`

- Reopening or rolling the dnstap output no longer stalls the server.
  ``5c92dc1769d``

  Every rndc dnstap -reopen, rndc dnstap -roll and every automatic roll
  of a size-limited dnstap-output file stopped all of named's processing
  until whatever was already running, such as an RPZ zone update, had
  finished and the old output had been flushed, closed and replaced. The
  output is now switched over while the server keeps running; the few
  dnstap messages produced during the switch itself are dropped and
  counted in the dnstap statistics. Logging to a size-limited output
  also no longer checks the file on disk for every message. :gl:`#6461`
  :gl:`!12934`

- Push initial packet explicitly in quic tests. ``7effce0661f``

  Not all versions of ngtcp2 can reproduce the client header when pulled
  from again.

  This caused a hang in the QUIC unit test when running from the 9fips
  CI image. :gl:`#6479` :gl:`!12992`

- Validate DELEG namelist with dns_name_fromwire() ``29611a24748``

  When reading a DELEG record off the wire, check each server-name in
  the rdata for correctness by processing it with `dns_name_fromwire()`.
  This avoids a possible assertion failure when running
  `dns_rdata_checknames()` later. :gl:`#6491` :gl:`!13043`

- Align the checkconf root KSK cutoff with named-checkconf.
  ``c28393ede02``

  The checkconf system test stopped expecting a warning for a root trust
  anchor containing only the 2026 KSK at 00:00 UTC on 11 October 2026,
  while named-checkconf keeps warning until 23:59 UTC that day, so every
  pipeline failed the test for that one day. The test now uses the same
  cutoff as the checker. :gl:`!12926`

- Fix the UDP receive buffer size for libuv recvmmsg. ``6d2063ae829``

  libuv splits the UDP receive buffer into UV__UDP_DGRAM_MAXSIZE (64 *
  1024) byte chunks, so a buffer of 20 * UINT16_MAX bytes only holds 19
  chunks and the last datagram slot of every recvmmsg call went unused.
  Size the buffer as 20 * 64 KiB so that all 20 slots are usable.
  :gl:`!12963`

- Handle dns_resolver_createfetch() failures in zonefetch.
  ``041989b354b``

  When `dns_resolver_createfetch()` is called by `dns_zonefetch_run()`
  and immediately fails - for example, when it gets `DNS_R_NXDOMAIN`
  from `dns_view_bestzonecut()` - the completion handler for the zone
  fetch must be called with the result code.

  Previously, a cancel handler was called instead, but that didn't take
  a result code and wasn't always able to handle failures correctly.  We
  now call the `done_fetch` callback and the `cancel_fetch` callback has
  been removed.

  Additionally, the `start_fetch` callbacks have been cleaned up to
  ensure that `fetch->qname` and `fetch->qtype` are always initialized
  even in the event of failure. :gl:`!13042`

- Remove duplicated dns_db_commitupdate() call in ixfr_apply_one()
  ``177b61e34d1``

  Commit da53708dcb "Implement qpzone specific update path" added a
  second dns_db_commitupdate() call right above the existing one. It is
  harmless because commitupdate is required to be safe to double-call,
  but it is dead code with a comment that duplicates the one below it.
  Keep a single call and merge the two comments. :gl:`!13028`

- Restore the 1024-bit minimum RSA key length in dnssec-policy.
  ``cb5589ab2a0``

  Commit e0ca243a93 lowered the non-FIPS minimum to 512 bits for all RSA
  algorithms except RSASHA512. That was wrong. Use minimum 1024 for all
  RSA algorithms outside FIPS mode. :gl:`!13051`

- Update the Extended DNS Error codes. ``26132b2b667``

  IANA has registered several new EDE codes since the last time the list
  was updated; we can now display them correctly. :gl:`!12936`

- Wrong algorithm names were shown for PRIVATEOID based DNSSEC keys.
  ``849eec4ee0b``

  Output that names a key's algorithm — "rndc dnssec -status", key event
  log messages, and the dnssec-keygen, dnssec-keyfromlabel and
  dnssec-ksr utilities — displayed the wrong algorithm for keys using
  the PRIVATEOID based algorithms: the value was truncated and shown as
  a different algorithm or a bare number (for example "0" instead of
  "RSASHA256OID"). All of these places now print the correct algorithm
  mnemonic. :gl:`!12712`


