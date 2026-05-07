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

BIND 9.21.22
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix outgoing zone transfers' quota issue. ``3ddd7b8695``

  Unauthorized clients could consume outgoing zone transfers quota and
  block authorized zone transfer clients. This has been fixed.
  :gl:`#3589`

- [CVE-2026-3592] Limit resolver server list size. ``e249148d75``

  When resolving a domain with many nameservers that share overlapping
  IP addresses (e.g., 10 NS records all pointing at the same set of
  addresses), BIND could previously waste time querying duplicate
  addresses and build up excessively large server lists.  Deduplicate
  addresses in the resolver's server list so that each unique IP is only
  queried once per resolution attempt, regardless of how many NS records
  point to it and cap the number of addresses stored per nameserver name
  to 6 (combined A and AAAA), preventing memory and CPU overhead from
  domains with unusually large NS/glue sets. :gl:`#5641`

- [CVE-2026-3039] Fix GSS-API resource leak. ``01bdb7abeb``

  Fixed a memory leak where each GSS-API TKEY negotiation leaked a
  security context inside the GSS library. An unauthenticated attacker
  could exhaust server memory by sending repeated TKEY queries to a
  server with tkey-gssapi-keytab configured. The leaked memory was
  allocated by the GSS library, bypassing BIND's memory accounting.

  Multi-round GSS-API negotiation (GSS_S_CONTINUE_NEEDED) is now
  rejected, as BIND never supported it correctly and Kerberos/SPNEGO
  completes in a single round. :gl:`#5752`

- [CVE-2026-5946] Disable recursion, UPDATE, and NOTIFY for non-IN
  views. ``21c8ba4f0b``

  Recursion, dynamic updates (UPDATE), and zone change notifications
  (NOTIFY) are now disabled for views with a class other than IN (such
  as CHAOS or HESIOD); authoritative service for non-IN zones (e.g.
  version.bind in class CHAOS) continues to work as before. Servers
  configured with recursion yes in a non-IN view will log a warning at
  startup, and named-checkconf flags the same condition. UPDATE and
  NOTIFY messages that specify the meta-classes ANY or NONE in the
  question section are now rejected with FORMERR.

  This addresses a set of closely related security issues collectively
  identified as CVE-2026-5946. ISC would like to thank Mcsky23 for
  bringing these issues to our attention. :gl:`#5784`

- [CVE-2026-5950] Avoid unbounded recursion loop. ``5319c21761``

  A bug during bad server handling could cause the resolver to enter an
  infinite loop, continuously sending queries to an upstream server with
  no exit condition, until the resolver query timeout was hit. This has
  been fixed.

  ISC would like to thank Billy Baraja (BielraX) for bringing this issue
  to our attention. :gl:`#5804`

- [CVE-2026-5947] Fix crash in resolver when SIG(0)-signed responses are
  received under load. ``9831f41894``

  A resolver could crash when handling a SIG(0)-signed response if the
  matching client query was cancelled while signature verification was
  still in progress — for example, when the recursive-clients quota was
  exhausted. This has been fixed. :gl:`#5819`

- Fix race condition in getsigningtime() ``d35a527ffb``

  Compute qpzone_get_lock(elem->node) into a local variable while the
  heap lock is still held, rather than dereferencing the stale elem
  pointer after releasing the lock. A concurrent thread running
  setsigningtime() (e.g. via IXFR apply on a worker thread) could free
  the top-of-heap element between the heap lock release and the
  dereference, causing a use-after-free. :gl:`#5883` :gl:`!11875`

- [CVE-2026-3593] Fix use-after-free in DNS-over-HTTPS when processing
  HTTP/2 SETTINGS frames. ``e33ff6bb0a``

  A use-after-free vulnerability in the DNS-over-HTTPS implementation
  could cause named to crash when a client sends a flood of HTTP/2
  SETTINGS frames while a DoH response is being written. This affects
  servers with DoH (DNS-over-HTTPS) enabled.

  ISC would like to thank Naresh Kandula Parmar (Nottiboy) for reporting
  this.

  For: #5755

New Features
~~~~~~~~~~~~

- Add DTRACE probes to the delegation cache. ``780ffe375f``

  The new delegation cache, which stores NS-based and DELEG-based
  delegations per view, is now instrumented with static user-space
  tracing probes so that cache hit rate, insertion and lookup latency,
  eviction pressure under memory limits, and removals triggered by rndc
  flush-delegation can be observed on a running named. :gl:`!11855`

Removed Features
~~~~~~~~~~~~~~~~

- Remove obsolete KEY record flags deprecated by RFC 3445.
  ``1535b32dab``

  KEY resource records originally defined NOAUTH, NOCONF, EXTENDED, and
  ENTITY flags that were removed by RFC 3445 back in 2002. BIND still
  carried code to parse and emit them, including the additional
  two-octet flags field that followed when the EXTENDED bit was set.
  That handling has been removed and the affected bit positions are now
  reserved.

  Dropping the extended-flags handling also eliminates a possible crash
  that could be reached when signing a zone containing an invalid key.
  :gl:`#5900` :gl:`!11961`

Feature Changes
~~~~~~~~~~~~~~~

- Embed default sanitizer flags in executables. ``7c60b7da8a``

  Replicating CI failures requires the developer to piece together the
  sanitizer flags by hand, reducing ergonomics.

  Fix this problem by embedding the relevant settings to the
  executables. Symbol resolution still needs manual intervention by
  setting the env variable `*SAN_SYMBOLIZER_PATH`. However, this doesn't
  affect any behavior.

  The flags are passed though a meson-configured `sanitize.c.in`
  template file to toggle which flags are included for the executable.
  Using the built-in `__SANITIZE_XXX__` or `__has_feature` for this task
  is more trouble than it's worth because only one of the two is
  available in most GCC/clang versions, alongside the lack of
  `__SANITIZE_UNDEFINED__` from GCC.

  Meson's own unit test execution sets its own `ASAN_OPTIONS` etc. To
  prevent it from overriding the default options, we also pass the same
  options to unit tests environment variables.

  A new script `ci/sanitizer-default-check.py` is used in CI to detect
  if a build directory with sanitizers enabled has a meson `executable`
  definition that doesn't include the sanitizer flag source file.
  :gl:`#5469` :gl:`!10919`

- Catch rare named crash in recursive resolution earlier for diagnosis.
  ``3c9a848be7``

  A rare crash has been observed in named while it is resolving upstream
  nameserver addresses for a recursive query, surfacing as a
  segmentation fault with no immediate clue as to the cause. This change
  adds internal consistency checks so that a future occurrence of the
  same condition aborts named with a diagnostic message at the point the
  inconsistency arises, rather than corrupting state and crashing later
  in an unrelated location. :gl:`#5602` :gl:`!11943`

- Revert isdelegation() to return boolean value again. ``69d439cd1b``

  :gl:`#5838` :gl:`!11792`

- Fix CPU spikes and slow queries when cache approaches memory limit.
  ``2e7e9f51db``

  Spread cache cleanup probabilistically to avoid CPU usage spikes and a
  drop in query throughput. :gl:`#5891`

- Add a refcount to the vecheaders. ``a743ff1e44``

  This MR changes the way the ownership of the vecheaders is tracked.
  Before this MR, the ownership of the vecheader was implicitely tracked
  through a mix of the refcount on the node owning the header, the
  external refcount of the same node and the version. This has some
  adverse consequences in terms of contention, such as that querying A
  and AAAA glue hits the same refcount.

  This MR adds a refcount to the vecheader itself, allowing it to exist
  independently of the node it is contained in. On its own, this would
  create a cycle, where the node has a reference to the header, which
  has a reference to the heap, which in turn has a reference to the
  node.

  To break this cycle, this MR also moves from an "intrusive" heap, to a
  more traditional one where pointers to the node and vecheader in the
  heap are stored in a hashmap. :gl:`!11397`

- Change NSEC3 and NSEC3PARAM rdata struct fields to use isc_region_t.
  ``245c71dfac``

  Replace the separate pointer+length field pairs in the NSEC3 and
  NSEC3PARAM rdata structures (salt/salt_length, next/next_length,
  typebits/len) with isc_region_t, making the fields self-describing and
  eliminating a class of length-mismatch bugs. :gl:`!11592`

- Document that named-checkzone must not run on untrusted input.
  ``5b164b551f``

  The zone-file parser implements $INCLUDE by opening whatever local
  path the zone text names, and fragments of the included file leak
  through parser error messages. There is no safe way to validate
  untrusted zone text with named-checkzone or named-compilezone, so the
  manual pages for both tools now warn against doing so. :gl:`!11901`

- Don't set named curves explicitly in pre-3.0 libcrypto. ``2e92389905``

  The function EC_KEY_set_asn1_flag is deprecated in AWS-LC. Fortunately
  calling it to make sure we use named curve keys is entirely
  unnecessary.

  More information for pre-3.0 libcrypto and significant forks are as
  following:

  OpenSSL: Named curves were the default between 1.1.0 and 3.6.1 [1],[2]

  AWS-LC: Library only supports named curves in the first place [3]

  BoringSSL: Likewise with AWS-LC [4]

  LibreSSL: EC_GROUPs are named by default [5]

  [1]: https://github.com/openssl/openssl/commit/86f300d38540ead85543aee
  0cb30c32145931744 [2]: https://github.com/openssl/openssl/commit/9db6a
  f922c48c5cab5398ef9f37e425e382f9440 [3]: https://github.com/aws/aws-lc
  /blob/a605df416bc6ddd0a3b79d728770664ce2302e71/include/openssl/ec_key.
  h#L442-L445 [4]: https://github.com/google/boringssl/blob/514abb73bb80
  130000b46cf589190c967c6647cd/include/openssl/ec_key.h#L279-L280 [5]: h
  ttps://github.com/libressl/openbsd/blob/c9338745181f31ae01336081edfdb7
  38c0b76d5f/src/lib/libcrypto/ec/ec_lib.c#L94 :gl:`!11530`

- Fix off by one error in dnssec-ksr sign. ``ae739daec2``

  If the inception time of the signature is exactly equal to the
  inactive time of the key, add the signature. :gl:`!11791`

- Harden GSS-API context establishment in TKEY negotiation.
  ``9212e1ac50``

  Implement RFC 3645 Section 3.1.1 client-side check for REPLAY, MUTUAL,
  and INTEG flags after gss_init_sec_context() completes.  Add
  server-side INTEG flag check after gss_accept_sec_context().  Also
  fixes an uninitialized gss_name_t on the error path in
  dst_gssapi_initctx().

- Implement RFC 3645 Section 4.1.1 key expiry check in TKEY.
  ``6b6913c83b``

  Check for existing TSIG keys before accepting a new GSS-API
  negotiation and delete the key if it has expired. Previously, an
  expired GSS key would permanently block re-negotiation for that name
  until the server was restarted. :gl:`!11713`

- Reduce memory footprint by actively returning unused memory to the OS.
  ``460bf794a5``

  Previously, :iscman:`named` relied on the default allocator settings
  for releasing unused memory back to the operating system, which could
  result in unnecessarily high resident memory usage. :iscman:`named`
  now actively manages memory page purging. On systems using jemalloc,
  background cleanup threads are enabled and the dirty page decay time
  is reduced from 10 seconds to 5 seconds. Additionally, a volume-based
  decay pass is triggered after every 16 MiB of freed memory.  On
  glibc-based systems, a similar volume-based mechanism using
  malloc_trim() is used instead. :gl:`!11761`

- Split up zone.c (zone manager) ``e99b5f80be``

  In order to make `zone.c` more readable, split it up in separate
  source files. This moves zone manager related code to  `zonemgr.c`.
  :gl:`!11726`

- Split up zone.c (zone properties) ``36acc92131``

  In order to make `zone.c` more readable, split it up in separate
  source files. This moves most of the set and get functions to
  `zoneproperties.c`. :gl:`!11501`

Bug Fixes
~~~~~~~~~

- Check validator name when adding EDE text. ``a6b44a6007``

  When a validator is being shut down, the associated name `val->name`
  is set to NULL.  This could cause a crash if a worker thread
  subsequently added an EDE code with `val->name` in the extra text.

  `validator_addede()` now checks whether the name is NULL before trying
  to add it to the extra text. :gl:`#5613` :gl:`!11945`

- Use the zone file's basename as origin in DNSSEC tools. ``08fa344014``

  In `dnssec-signzone` and `dnssec-verify`, when the zone origin is not
  specified using the `-o` parameter, the default behavior is to try to
  sign using the zone's file name as the origin. So, for example,
  `dnssec-signzone -S example.com` will work, so long as the file name
  matches the zone name.

  This now also works if the zone is in a different directory. For
  example, `dnssec-signzone -S zones/example.com` will set the origin
  value to `example.com`. :gl:`#5678` :gl:`!11360`

- Fix a possible race condition during zone transfers. ``175b121bc3``

  The :iscman:`named` process could terminate unexpectedly when
  processing an IXFR message during a zone transfer. This has been
  fixed. :gl:`#5767` :gl:`!11781`

- Do not resend query after BADCOOKIE answer on TCP. ``53593e8e13``

  When an upstream server answers BADCOOKIE, no matter which transport
  is used, the resolver resends the query using TCP. However, if the
  upstream server responded with BADCOOKIE again over TCP, the resolver
  would keep resending until the maximum query count was reached.

  This is now fixed by no longer resending once the query has already
  been sent over TCP. :gl:`#5804`

- Make BIND9 compatible with OpenSSL 4. ``80794c5e87``

  OPENSSL_cleanup() in OpenSSL 4 doesn't free the memory, and that is
  not compatible with BIND 9's memory leak detection code. Don't use
  custom allocation/deallocation functions for OpenSSL's internal memory
  management.

  See https://github.com/openssl/openssl/pull/29721 :gl:`#5808`
  :gl:`!11865`

- Fix named crash when processing SIG records in dynamic updates.
  ``5f0b2f255f``

  Previously, :iscman:`named` could abort if a client sent a dynamic
  update containing a SIG record (the legacy signature type) to a zone
  configured with an update-policy. The function `dns_db_findrdataset`
  had an incorrect requirements prerequisite that prevented SIG records
  being looked up, which was triggered as part of processing an UPDATE
  request and could be triggered remotely by any client permitted to
  send updates. This has been fixed by ensuring that SIG records are
  handled consistently with RRSIG records during update processing.
  :gl:`#5818` :gl:`!11864`

- Fix wrong NSEC proof for empty non-terminals after IXFR.
  ``15f058b5a2``

  When a secondary received an IXFR that transitioned a zone from
  unsigned to NSEC-signed, queries for empty non-terminal names returned
  the zone apex NSEC record instead of the NSEC that actually covers the
  queried name.  The issue only occurred with incremental transfers; a
  full AXFR or a server restart resolved it. :gl:`#5824` :gl:`!11786`

- Fix rndc modzone behavior for a zone in named.conf. ``c56d4c13f9``

  If a zone was present in the configuration file and not originally
  added by `rndc addzone`, `rndc modzone` for that zone would succeed
  once but subsequent `modzone` attempts would fail. This has been
  fixed. :gl:`#5826` :gl:`!11744`

- Fix zone verification of NSEC3 signed zones. ``0633effb5b``

  Previously, when computing the compressed bitmap during verification
  of an NSEC3-signed zone, an undersized buffer was used that resulted
  in an out-of-bounds write if there were too many active windows in the
  bitmap. This impacted mirror zones which are NSEC3-signed,
  `dnssec-signzone` and `dnssec-verifyzone`. This has been fixed.
  :gl:`#5834` :gl:`!11804`

- Fix 'rndc modzone' issue with non-existing zones. ``09a4b80301``

  The :iscman:`named` process could terminate unexpectedly or become
  subject to undefined behavior when issued an :option:`rndc modzone`
  operation for a non-existing zone. This has been fixed. :gl:`#5848`
  :gl:`!11844`

- Fix zone filename token-parsing bug. ``ef29555ba4``

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog member zone containing special characters like
  '%' or '$' which could be interpreted as zone filename tokens and
  trigger a case-sensitivity bug in the token-parsing code. This has
  been fixed. :gl:`#5849` :gl:`!11839`

- Prevent a crash when using both dns64 and filter-aaaa. ``3c60322fa3``

  An assertion failure could be triggered if both `dns64` and the
  `filter-aaaa` plugin were in use simultaneously. This happened if the
  plugin triggered a second recursion process, which then attempted to
  store DNS64 state information in a pointer that had already been set
  by the original recursion process. This has been fixed. :gl:`#5854`
  :gl:`!11949`

- Remove unnecessary dns_name_free call. ``bbdca691c0``

  When processing a catalog zone member's primaries definition and there
  is a TXT record containing an invalid name TSIG key name,
  dns_name_free was incorrectly called triggering an assertion. This has
  been fixed. :gl:`#5858` :gl:`!11832`

- Prevent malicious DNSSEC zones from exhausting validator CPU.
  ``120eaf546f``

  A DNSSEC-signed zone could publish a DNSKEY with an unusually large
  RSA public exponent and force any validator resolving names in that
  zone to spend disproportionate CPU verifying signatures.  The
  validator now rejects such DNSKEYs, matching the limit already applied
  to keys read from files or HSMs. :gl:`#5881` :gl:`!11917`

- Add missing parenthesis to fxhash. ``a8d412ab21``

  The fxhash implementation had a missing parenthesis that caused it to
  diverge from Rust's reference implementation. This commit fixes this.
  :gl:`#5882` :gl:`!11857`

- Fix strict weak ordering violation in resign_sooner() ``13a6867757``

  resign_sooner_values() only checked whether rhs was SOA-typed when
  resign times were equal, but did not check lhs. When both entries were
  SOA-typed with equal resign times, the comparison returned true in
  both directions, violating irreflexivity and corrupting heap
  invariants.

  Add lhs_typepair parameter and require lhs to be non-SOA for the
  tie-breaking logic to apply. :gl:`#5884` :gl:`!11874`

- Fix inverted gethostname() check in rndc status. ``4a8c6a0933``

  The replacement of named_os_gethostname() with raw gethostname()
  inverted the success check: the "localhost" fallback runs on success,
  and on failure the uninitialized hostname buffer is read by
  snprintf(), leaking stack memory via the rndc status reply.
  :gl:`#5889` :gl:`!11879`

- Fix rndc-confgen aborting on HMAC-SHA-384/512 keys above 512 bits.
  ``c137dcd1a4``

  `rndc-confgen -A hmac-sha384` and `-A hmac-sha512` documented a `-b`
  range of 1..1024, but any value above 512 aborted on hardened builds
  instead of producing a key. The full advertised range now works.
  :gl:`#5903` :gl:`!11903`

- Validate key names in rndc-confgen, tsig-keygen, ddns-confgen.
  ``b8e09a5b5f``

  The three tools embedded the key-name argument verbatim into the
  generated `named.conf` block, so a name containing characters like
  `"`, `{`, or `;` produced output that did not match the intended `key`
  clause. Key names are now restricted to letters, digits, dots,
  hyphens, and underscores. :gl:`#5904` :gl:`!11904`

- Do not follow symlinks when chowning the NZD database. ``ce77138b5c``

  When `named` runs as root, the per-view NZD database file is chowned
  to the user `named` drops to. The chown call followed symlinks, so a
  symlink at the database path could redirect the ownership change to an
  unrelated file. The chown now refuses non-regular files and never
  follows symlinks. :gl:`#5905` :gl:`!11907`

- Prevent crafted queries from degrading RRL performance. ``cf18479882``

  With response rate limiting enabled, an attacker sending queries from
  many spoofed source addresses could steer entries into the same slot
  of the internal rate-limit table and slow down query processing on the
  affected server. The table now uses a per-process keyed hash so the
  placement of entries cannot be predicted or influenced from the
  network. :gl:`#5906` :gl:`!11950`

- Fix swapped arguments in redirect2() single-label branch.
  ``f5853e765f``

  On a recursive resolver with nxdomain-redirect configured, an NXDOMAIN
  result for a query whose qname is the root could corrupt the view's
  nxdomain-redirect target, after which the redirect feature stopped
  working for every subsequent query in that view until named was
  restarted. :gl:`#5908` :gl:`!11908`

- Avoid named assertion failure during parent-NS lookups when none
  exist. ``90c7385000``

  Configuring the root zone as a signed primary with parental agents (or
  with notify-on-cds-changes) caused named to exit on an internal
  assertion as soon as the DS-publication machinery tried to look up the
  parent NS RRset — the root has no parent. The lookup is now
  short-circuited cleanly.

  Similar, a zone with no NS records in the parent caused named to exit
  in the same way. :gl:`#5910` :gl:`!11909`

- Remove the rndc testgen command. ``28025ceff8``

  testgen existed only to let the rndc system test generate large
  response payloads. It accepted an unbounded count and was reachable
  from read-only control channels, so any read-only rndc client could
  drive named into memory exhaustion. The command and its supporting
  test helper are gone; remaining rndc commands already produce
  non-trivial responses, so transport coverage is preserved. :gl:`#5911`
  :gl:`!11912`

- Free per-command rndc state when response serialisation fails.
  ``bf7ee390ba``

  When isccc_cc_towire failed while building an rndc reply,
  control_respond returned without releasing the per-command request,
  response, HMAC secret copy, and text buffer.  They were eventually
  freed when the connection closed, but until then the HMAC key copy
  stayed in named's memory.  The failure path now goes through the same
  cleanup label as every other error. :gl:`#5913` :gl:`!11915`

- Handle KSR files with DNSKEY records before any header. ``55213079c6``

  A DNSKEY record appearing before the first ';; KeySigningRequest'
  header in a KSR file made dnssec-ksr abort on an internal assertion
  instead of producing a structured error, killing pipelines that fed it
  crafted or corrupted input.  The tool now exits with a fatal error
  naming the file and line. :gl:`#5914` :gl:`!11916`

- Prevent rare named crash when notifies are cancelled. ``d079ca1b92``

  Under heavy load, named could occasionally crash when a queued
  outbound notify or zone refresh was cancelled at the moment it was
  being sent — for example, while a zone was being reloaded or removed.
  The race that caused the crash is now prevented. :gl:`#5915`
  :gl:`!11918`

- Stop delv from aborting on a malformed query name. ``ddf6239534``

  delv aborts with SIGABRT instead of exiting cleanly when given a query
  name that fails wire-format conversion (e.g. a label longer than 63
  octets). After this change delv prints the parse error and exits with
  a normal failure code. :gl:`#5916` :gl:`!11921`

- Fix dig -x crash on excessively long arguments. ``62ced63e22``

  dig -x crashed with a segmentation fault rather than printing an error
  when given an argument with thousands of dot-separated components. dig
  -x now rejects such inputs cleanly with "Invalid IP address".
  :gl:`#5917` :gl:`!11928`

- Reject RSA DNSKEYs with degenerate modulus. ``d455794d0d``

  A crafted DNSKEY rdata whose declared exponent length consumed the
  whole buffer produced an RSA key with no modulus, which
  dnssec-importkey accepted as valid and wrote to a .private file with
  no key material. The wire-format parser now rejects RSA public keys
  with a modulus smaller than 512 bits, the lowest legitimate size
  across the RSA DNSSEC algorithms. :gl:`#5920` :gl:`!11929`

- Reject negative and out-of-range TTLs in dnssec-* tools.
  ``31818f6417``

  The dnssec-* tools accepted negative and out-of-range values for TTL
  flags such as dnssec-keygen -L, dnssec-signzone -t and dnssec-settime
  -L, silently turning them into TTLs of around 136 years in the
  resulting key or zone files. The flag values are now validated and
  rejected with a clear "TTL must be non-negative" or "TTL out of range"
  error. :gl:`#5923` :gl:`!11933`

- Fix a crash when reconfiguring while an NTA is being rechecked.
  ``386177ec67``

  When named was reconfigured or shut down while a negative trust anchor
  was being rechecked against authoritative servers, the in-flight
  recheck could outlive the view that owned it and cause `named` to
  crash.  This has been fixed. :gl:`#5938` :gl:`!11948`

- Fix a bug in allow-query/allow-transfer catalog zone custom
  properties. ``774e08dee3``

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog zone with an invalid ``allow-query`` or
  ``allow-transfer`` custom property (i.e. having a non-APL type)
  coexisting with the valid property. This has been fixed. :gl:`#5941`
  :gl:`!11954`

- Fix a stack use-after-free in qpzone. ``82f67fc633``

  In previous_closest_nsec(), a new qpreader was opened to search the
  NSEC tree. It was possible for that to be used to update a QP iterator
  object owned by the caller, and then be destroyed when the function
  returned.

  This qpreader object isn't necessary anymore; since namespaces were
  added to the QP trie in commit 15653c54a0, we can now just reuse the
  existing reader for the main tree. :gl:`#5942` :gl:`!11955`

- Fix a memory leak issue in the catalog zones. ``deb3694a63``

  The :iscman:`named` process could leak small amounts of memory when
  processing a catalog zone entry which had defined custom primary
  servers with TSIG keys using both the regular ``primaries`` custom
  property syntax and the legacy alternative syntax (``masters``) at the
  same time. This has been fixed. :gl:`#5943` :gl:`!11951`

- Avoid extra round trips for DS lookups when the parent delegation is
  already cached. ``07c8cddb4c``

  DS queries could take two unnecessary extra round trips when the
  resolver sent them to the child zone instead of the parent. The child
  responds with NODATA, forcing a recovery path to rediscover the parent
  delegation even though it was already cached.  The resolver now
  consults its delegation cache before starting DS fetches, sending
  queries directly to the correct parent nameservers and eliminating the
  extra latency. :gl:`!11835`

- Enforce dns_adb_createaddrinfofind() invariant. ``bb330e533b``

  ADB `dns_adb_createaddrinfofind()` expects `maxaddrs` paramaters is
  always strictly positive. Add an assertion to enforce it. :gl:`!11819`

- Fix a bug with template filename reuse. ``cf11b88e0e``

  When a zone filename is defined in `named.conf` which will be written
  to by the server - i.e., for secondary or dynamically updated zones -
  there is a test at configuration time to ensure that the filename is
  non-unique.

  This test is run before the zone is actually created, so a zone
  configured using a template may not have had its filename expanded
  yet.  This can cause a configuration to fail because, for example,
  multiple zones appear to using the filename `$name.db`.      This has
  been fixed by adding a new function `dns_zone_expandzonefile()` and
  calling it during the uniqueness check. :gl:`!11769`

- Fix suppressed missing-glue check in named-checkzone. ``e75f146485``

  named-checkzone and named-checkconf -z silently skipped the
  missing-glue check for any NS name that had already triggered an
  extra-AAAA-glue warning, so zones missing required A glue could pass
  validation and be deployed with broken delegations. :gl:`!11899`

- Glues from different parent are rejected. ``48d098467f``

  The changes making BIND 9 parent-centric !11621 introduced an issue
  where it could be possible, when processing a referral, to use the
  glue to a nameserver which has a different parent than the zonecut.
  For instance:

  AUTHORITY         test.example.           NS      ns.test.example.
  test.example.           NS      ns.foo.example.         test.example.
  NS      ns.bar.                  ADDITIONAL         ns.bar.
  A       1.2.3.4         ns.foo.example.         A       5.6.7.8
  ns.test.example.        A       9.8.7.6

  In such situation, only the glues for `ns.foo.example.` and
  `ns.test.example.` should be used, and the glue from `ns.bar.` must be
  ignored as this is not either a sub-domain or a sibling domain, the
  parent is different (`bar.` instead of `example.`). This is now fixed.

  Sibling glue and cyclic sibling glues are defined in RFC 9471 section
  2.2 and section 2.3. :gl:`!11873`

- Harden dig's EDNS option parsing against malformed replies.
  ``7b87ab0236``

  dig's parser for EDNS options in a DNS reply now stops cleanly when an
  option declares a length that runs past the end of the option data,
  rather than trusting the upstream OPT-record validator to reject the
  reply first. This is a defensive change; behavior is unchanged in
  practice. :gl:`!11937`

- Implement seamless outgoing TCP connection reuse. ``a61427e8ee``

  The resolver can and will reuse outgoing TCP connections to the same
  host, as recommended by RFC 7766. This prevents a whole class of
  attacks that abuse the fact that establishing a TCP connection is
  expensive and it is fairly easy to deplete the outgoing TCP ports by
  putting them into TIME_WAIT state.

  The number of pipelined queries per connection is capped at 256 to
  limit the impact of a connection drop. :gl:`!11845`

- Include <sys/endian.h> according by checking in meson. ``f27aba4d7d``

  The <sys/endian.h> header has existed in macOS since around ~26. This
  causes the `htobeNN`/`htoleNN` macros to be redefined in
  <isc/endian.h> in terms of <libkern/OSByteOrder.h> when other system
  headers include <sys/endian.h>.

  Fix this issue by using checking for the existence of <sys/endian.h>
  in meson and including it according to the probe result. :gl:`!11751`

- Pass empty string instead of NULL to ns_client_dumpmessage()
  ``a0084190b4``

  Pass "" instead of NULL to ns_client_dumpmessage() to get the log
  message printed.

- Possible crash when a resolver validate a static-stub zone.
  ``b8dcabbd72``

  A NULL pointer dereference could be made in some circumstances when
  resolving and validating a name under a `static-stub` zone. This is
  now fixed. :gl:`!11788`

- Prevent excessive priming queries to the root servers. ``5f8624df76``

  BIND was sending a priming query to the root servers on nearly every
  recursive lookup instead of only when the cached root information
  expired.  Priming now rearms only after the TTL of the fetched records
  elapses, and the refreshed root NS set is used for query routing until
  the next cycle. :gl:`!11847`

- Reject record sets too large to serve in DNS. ``a925af7ce6``

  When BIND was asked to store a record set whose total size exceeds
  what fits in a DNS message, it would allocate memory and build the
  structure, then fail later at response time. Such oversized record
  sets are now rejected at the time of storage with an error, avoiding
  wasted work on data that can never be served. :gl:`!11963`

- Remove deadcode in `query_addbestns()` ``43c58dafcc``

  The local variable `zfname` was released in the cleanup part of the
  function if not NULL, but it turns out it is now always NULL at that
  point.

  The flow can get to that part only in two cases: either `zfname` is
  not NULL, and then it's ownership is moved to a different variable
  (thus, it is now NULL), or `zfname` is already NULL.

  Removing the bit of deadcode releasing it. :gl:`!11790`

- Remove unneeded options in dns_zonefetch. ``a43a6cfba4``

  In the `dns_zonefetch` mechanism, some option flags for
  `dns_resolver_createfetch()` were used for all fetches, but were
  actually only needed by the `DNSKEY` refresh fetches.

  (Specifially, these options were `DNS_FETCHOPT_UNSHARED` and
  `DNS_FETCHOPT_NOCACHED`, which were used along with
  `DNS_FETCHOPT_NOVALIDATE` to ensure we get a new copy of the DNSKEY as
  it is currently published by the authority, without prior validation.
  Those conditions are needed for RFC 5011 trust anchor maintenace, but
  not when looking up parent-`NS` or `DSYNC` RRsets.) :gl:`!11866`

- Stop rndc-confgen from following symlinks when writing the keyfile.
  ``468b09feb2``

  When rndc-confgen -a (re)created the rndc control key, it followed a
  symbolic link if one happened to exist at the keyfile path: the
  existence check looked through the link, then the file was truncated,
  its ownership changed, and the key contents written into whatever file
  the link pointed at. rndc-confgen now refuses to follow symbolic links
  at the keyfile path and fails with an error instead, so the wrong file
  can no longer be overwritten by accident. :gl:`!11902`

- Validate -l and -L numeric arguments in named-checkzone.
  ``1064d11af2``

  named-checkzone and named-compilezone parsed the -l (max TTL) and -L
  (source serial) arguments with strtol(), so a negative value such as
  -1 silently became UINT32_MAX and out-of-range values were truncated
  to 32 bits without warning; -l in particular appeared to cap TTLs but
  no longer enforced anything. Both flags now go through
  isc_parse_uint32() and reject any value that is not a valid 32-bit
  unsigned integer. :gl:`!11900`


