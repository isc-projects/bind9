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

BIND 9.21.25
------------

New Features
~~~~~~~~~~~~

- Add a RPZ mode to named-checkzone. ``e245552b9d7``

  Provides a command line switch (named-checkzone -P) to treat the zone
  being loaded as an RPZ zone and check if the owner names are valid.
  :gl:`#262` :gl:`!12455`

- Disclose active Negative Trust Anchors with Extended DNS Error 33.
  ``8dae0a8cda5``

  A Negative Trust Anchor (RFC 7646) turns off DNSSEC validation for a
  domain, so a name that would normally fail validation resolves
  instead. named now marks such answers with Extended DNS Error code 33,
  "Negative Trust Anchor", so operators can see at a glance when a
  response came back only because an NTA was in effect. :gl:`#6268`
  :gl:`!12424`

- Add crypto required for quic support. ``f6d644b18fa``

  This MR adds the necessary cryptographic parts for QUIC support. These
  parts are:

  AEAD (AES-GCM and ChaCha20-Poly1305)

  HKDF (Both the original algorithm and TLS 1.3's HKDF-Expand-Label)

  QUIC header protection mask generation :gl:`!11549`

- Add development guidance for AI coding agents under .agents/skills/
  ``3a9477a4567``

  This adds a set of skill documents that give AI coding agents the
  project's established practices up front instead of having them
  rediscovered (or gotten wrong) in every session: the canonical build
  and test invocations, the memory-allocator contract, the disciplines
  for RCU mutation, per-loop sharded structures, struct-layout work, and
  flight-recorder debugging of concurrency bugs, plus the commit and
  merge-request conventions. :gl:`!12363`

- Add more unit tests for isc_time API. ``b443224f893``

  While working on internal 64-bit time for BIND 9, the unit test suite
  for isc_time API has been extended.

  Backport the unit tests from 64-bit time branch to the main branch.
  This should make the unit tests for isc_time API (mostly) complete.

  Related to #2959 :gl:`!5760`

- Built-in hints can be printed with named -H command. ``e9c4c2619de``

  Additionally root hints were updated to precisely match authoritative
  source including comments. This is a cosmetic change IP addresses
  haven't been changed. :gl:`!11114`

Removed Features
~~~~~~~~~~~~~~~~

- Remove unused closest encloser proof caching. ``de7f34fb44b``

  BIND used to cache an NSEC3 closest encloser proof alongside positive
  wildcard answers so that a resolver could re-send it when answering
  from its cache. That stopped being used in BIND 9.9 (2011), when
  positive wildcard responses were changed to omit that NSEC3 record —
  RFC 5155 requires only the next closer name proof — and the closest
  encloser came to be derived during validation instead. The caching
  code has been unreachable ever since, so this removes it with no
  change in behaviour. :gl:`#5803` :gl:`!11779`

Feature Changes
~~~~~~~~~~~~~~~

- Move wire-test to bin/tools/named-wireformat. ``4976573897e``

  `wire-test`, a testing tool which parses wire-format DNS data and
  displays it in human-readable form, has been renamed to
  `named-wireformat` and moved from `bin/tests/system` to `bin/tools`.
  :gl:`#2098` :gl:`!12442`

- Batch qp transaction for RPZ updates. ``08d0108a319``

  RPZ was built around fine-grained locking, but that forces the use of
  many small qp transactions. With this MR, we switch qp transaction to
  handle the full update to the rpz summary structure. While this
  serializes the RPZ updates, the reduced overhead from batching qp
  transactions more than compensates for it and results in improvements
  for big RPZ zones. :gl:`#5787`, #6270 :gl:`!12411`

- Delete cache rdatasets directly instead of tombstoning them.
  ``9da4f0c79d6``

  Deleting an rdataset from the cache left a placeholder entry behind
  that every lookup had to skip until it aged out. Deletion now removes
  the entry outright, and the placeholder mechanism is gone.
  :gl:`!12454`

- Do not attach authdb. ``ee52f963659``

  The authdb variable is used either to check that, on restarts, we do
  not cross to a different zone unless recursion is enabled, and to
  lookup the zone version when filling the additional section.

  Neither use requires the pointer to be attached, and attaching the
  pointer causes scalability issues. This commit solves the problem by
  turning the pointer into an integer id. :gl:`!12375`

- Pass the work callback result to the done callback. ``03024f24068``

  The `isc_work` callback now returns `isc_result_t` and the value is
  handed to the done callback, so the callers no longer need their own
  result-passing state. :gl:`!12390`

- Reduce the memory used by each record set in the cache.
  ``eb83d136a31``

  Each record set in the cache carried a 32-byte table for restoring its
  owner name's letter case, unused since the case handling was reworked.
  Removing it makes every cache entry 32 bytes smaller. :gl:`!12478`

- Unify the internal representation of negative cache entries.
  ``7688e668f52``

  Negative cache entries are now stored and exposed under the type whose
  nonexistence they prove instead of the old inverted encoding.
  :gl:`!12481`

- Use  project lints as tests in meson. ``319ea1237ac``

  The check scripts run in the CI job `misc` is also useful in
  development enough that it warrants an easy way to execute them all at
  once.

  Add these scripts as unit tests with the suite `lint`. :gl:`!12437`

- Use sanitizer.contains() instead of the "in" operator. ``c5009f851a8``

  muon's static analyzer aborts on the four "'address' in sanitizer"
  expressions because it cannot typecheck the "in" operator against the
  complex combo type it infers for b_sanitize, which makes "muon
  analyze" unusable on the whole tree.  Reported upstream as
  https://github.com/muon-build/muon/issues/289.

  Assisted-by: Claude:claude-fable-5 :gl:`!12459`

Bug Fixes
~~~~~~~~~

- Dig +yaml producing invalid YAML when a lookup fails. ``e748b6d2ab7``

  When "dig +yaml" was run and no server could be reached, dig printed
  its plain-text startup banner (the "; \<\<\>\> DiG ..." and ";; global
  options" lines) ahead of the machine-readable output, so the result
  was not valid YAML and could not be parsed. dig no longer emits that
  banner in YAML mode. As part of the same change, the banner is now
  built only after the whole command line has been read, so options
  given after the query name (such as +nocmd, +short and +yaml) are
  correctly reflected in it. :gl:`#1230` :gl:`!12416`

- Ensure NSEC authority does not cross zonecut boundary. ``d47b5ea79b3``

  When using a cached NSEC record to prove that a delegation is
  insecure, we now check that the signer name in the corresponding RRSIG
  is not above a known secure delegation point. This prevents a signed
  namespace from being downgraded to insecure using an NSEC record from
  the grandparent zone. :gl:`#5967` :gl:`!12257`

- Treat non canonical RPZ prefixes as any other failure. ``ce024934d52``

  RPZ prefixes that were not encoded in canonical form do not work.
  Treat them as any other encoding error. :gl:`#6043` :gl:`!12441`

- Prevent aborts during expired cache dumps. ``c07eae145ea``

  Running rndc dumpdb -expired could cause named to abort when the cache
  contained internal deletion markers for records that had already been
  removed. BIND now skips those markers when preparing expired cache
  dumps, so the dump includes only real cached records and completes
  normally. :gl:`#6064` :gl:`!12387`

- Properly prevent TSIG generation command line injection attacks.
  ``f47660dcb66``

  When key names are generated with `rndc-confgen`, `tsig-keygen` and
  `ddns-confgen`, special characters must be escaped to ensure the
  configuration is parsed correctly. :gl:`#6071` :gl:`!12395`

- Prevent ddns-confgen self-domain update-policy injection.
  ``680b168c86c``

  In `ddns-confgen`, the user-supplied domain name to be updated was not
  properly escaped and put inside a double-quoted string when generating
  the example code fragment.  This has been corrected. :gl:`#6072`
  :gl:`!12409`

- Dig with IDN output could leak memory on ISC_R_NOSPACE  retry.
  ``1b135fdfbb1``

  The IDN to text display call back could leak the memory holding the
  converted name if it did not fit into the buffer.  This has been
  fixed. :gl:`#6073` :gl:`!12462`

- Dnssec-signzone had a potential heap bounds overflow write.
  ``6bbcca04ec5``

  It was possible for `dnssec-signzone` to overflow array bounds while
  signing.  This has been fixed. :gl:`#6076` :gl:`!12491`

- Use correct port and target for NOTIFY(CDS) ``5fcb833118c``

  If there is a DSYNC RRset with multiple records, and unsupported
  scheme/type records follow supported ones, the port and target of the
  last record were being used to queue the notify. This does not
  necessarily match the port and target of the supported record. This
  has been fixed. :gl:`#6080` :gl:`!12376`

- Restore SMF support on Solaris and illumos. ``2987da1ca71``

  SMF support on Solaris and illumos was silently dropped by a build
  system rewrite in 2018; it is now detected and enabled again.
  :gl:`#6096` :gl:`!12369`

- Fix NULL pointer dereference in dnstap-read. ``a3405b1f000``

  It was possible to dereference a NULL pointer in dnstap-read causing
  it to exit on a malformed DNSTAP file.  This has been fixed.
  :gl:`#6124` :gl:`!12463`

- Change catz coo locking. ``b0a4f6b39d7``

  Catalog zones might need to inspect the change-of-ownership records of
  other catalog zones, which required to release the lock in the middle
  of certain operations, leading to possible race conditions.

  Since the operations on change-of-ownership records are limited, we
  can instead use a design with a second lock protecting the
  change-of-ownership records on read. We structure the API so that
  holding two change-of-ownership locks at the same time is impossible.
  :gl:`#6131` :gl:`!12277`

- Treat an unusable NSEC3 chain as a verification failure.
  ``c0a964549b9``

  When transferring in a mirror zone, DNSSEC verification could
  incorrectly succeed when the zone had an invalid `NSEC3PARAM` record,
  leading to subsequent validation failures. This has been fixed.
  :gl:`#6136` :gl:`!12408`

- Unterminated OpenSSL private-key `Label:` field can be read past its
  parser buffer. ``d5388f2067d``

  Check that the string encoded in the Label: field of the .private file
  of a key pair is NUL terminated and the correct length.  Reject the
  .private file if it is not. :gl:`#6193` :gl:`!12364`

- Dns_private_chains wasn't handling PRIVATE DNSSEC algorithms
  correctly. ``bc8baa06d9b``

  dns_private_chains wasn't looking for the private records that
  indicate that a zone is being signed by a PRIVATE DNSSEC algorithm.
  This has been fixed. :gl:`#6205` :gl:`!12461`

- Negative caching stopped working with stale-answer-client-timeout 0.
  ``512c9001681``

  With "stale-answer-client-timeout 0" configured, every client query
  for a name cached as NXDOMAIN or NODATA was sent on to the
  authoritative servers, even while the cached negative answer was still
  within its TTL, so the resolver effectively lost negative caching.
  Negative answers are now refreshed only once they have actually gone
  stale. :gl:`#6245` :gl:`!12381`

- MacOS byte swapping macros already defined. ``74c278020a4``

  Don't redefine them if the development environment already defines
  them. :gl:`#6250` :gl:`!12388`

- Use memmove in isc_sockaddr_fromin/isc_sockaddr_fromin6.
  ``f0f6fb16a70``

  Use memmove instead of direct assignment from the source pointer
  because the source pointer is not guaranteed to be correctly aligned.
  :gl:`#6260` :gl:`!12434`

- Fix TSIG keys creation/eviction ordering issue. ``2b71404eea5``

  When adding a new key into a full list, the newly inserted key could
  be evicted just after the insertion if all the existing keys were
  marked as visited. This has been fixed. :gl:`#6263` :gl:`!12400`

- Fix compilation on GNU/Hurd. ``c9900e7d14c``

  Fix compilation issues on GNU/Hurd. :gl:`#6285` :gl:`!12489`

- Fix recognition of DNSSEC keys using the PRIVATEDNS private algorithm.
  ``a169827d4ae``

  `dst_algorithm_fromprivatedns()` parses the algorithm name with
  `dns_name_fromwire()`, which reads only the buffer's active region;
  the callers in frombuffer() and the resolver never set it, so
  PRIVATEDNS keys were always rejected as unsupported. :gl:`!12485`

- QUIC crypto fixes. ``f9ed83bd6f8``

  The isc_crypto_aead_open() and isc_crypto_aead_seal() functions in
  ossl3.c didn't check if 'additional_data' exists before using it. The
  checks were in place in the ossl1_1.c implementation. Use the same
  conditions in the ossl3.c implementation too.

  Additionally, the ciphertext length passed to the EVP_DecryptUpdate()
  function included the tag length too which caused errors when
  decrypting. Use the 'len' variable instead which doesn't include the
  tag length. :gl:`!12413`

- Resolver could return expired records instead of a negative answer.
  ``886dff46c33``

  When an unvalidated negative answer (such as one obtained for a query
  with the "checking disabled" flag set) arrived for a name that had
  DNSSEC-validated records in the cache, those records blocked the
  negative answer from being cached even after they had passed their
  TTL, and the expired records could be returned to the client instead.
  Validated records that have expired no longer prevent negative answers
  from being cached. :gl:`!12423`

- Restore arc4random() detection dropped in the v9.21.14 merge.
  ``3eb9fde6d7c``

  Commit 4db9e5d90e2 ("Use arc4random for CSPRNG when available", part
  of the CVE-2025-40780 fix) guarded the arc4random() code paths in
  lib/isc/random.h and lib/isc/random.c with HAVE_ARC4RANDOM and added
  the corresponding function check to meson.build.  The manual conflict
  resolution in merge c2a672bbaef ("Merge tag 'v9.21.14'") kept the code
  changes but dropped the meson.build hunk, so HAVE_ARC4RANDOM was never
  defined and platforms with arc4random() (macOS and the BSDs) silently
  fell back to the internal ChaCha-based CSPRNG.  Restore the check.

  Assisted-by: Claude:claude-fable-5 :gl:`!12451`


