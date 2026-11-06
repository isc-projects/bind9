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

BIND 9.20.31
------------

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate NXDOMAIN redirection. ``c8dfd310902``

  The `nxdomain-redirect` option and `type redirect` zones are now
  deprecated. A warning will be generated when these are encountered in
  `named.conf`.

  Related to #6451 :gl:`!12935`

- Remove the atomic_ptr() wrapper. ``5afda8f0450``

  The wrapper has a single user and saves nothing over spelling out
  `_Atomic(type *)`.  Coccinelle cannot parse its definition, so the
  header costs the semantic patches a few lines of coverage for no
  benefit.

  Assisted-by: Claude:claude-opus-5-5 coccinelle :gl:`!12915`

Feature Changes
~~~~~~~~~~~~~~~

- Faster IXFR for inline-signed zones. ``f1b35ff11a3``

  Previously, the implementation of dns_diff_appendminimal could lead to
  quadratic complexity when used in a loop. We introduce an
  dns_diff_appendlistminimal method for diffs that uses an hashmap to
  minimize the diff, leading to linear complexity.

  ISC would like to thank Qifan Zhang, of Palo Alto Networks, for
  reporting this issue. :gl:`#5980` :gl:`!12911`

- Keep accepting CN-only certificates for DoH with OpenSSL 4.1.
  ``1657680098a``

  OpenSSL 4.1 no longer falls back to the Subject Common Name when a
  server certificate has no SubjectAltName, so "dig +https" started
  rejecting such certificates with a hostname mismatch.

  Ask for the Subject explicitly on OpenSSL 4.1 and later, which is the
  only way to keep the Common Name in play there; OpenSSL then also
  consults it alongside any SubjectAltName, the closest to the previous
  behaviour it offers.  Older releases keep their default, and DoT is
  unaffected because it never consulted the Subject.

  Assisted-by: Claude:claude-fable-5-1 :gl:`!12944`

- Minimize ANY responses over TCP when minimal-any is enabled.
  ``ef55a6723ca``

  When :namedconf:ref:`minimal-any` was enabled, BIND minimized ANY
  responses over UDP but returned all available RRsets over TCP. BIND
  now returns a single RRset, with its covering RRSIGs when requested,
  and omits unnecessary authority and additional data regardless of
  transport. :gl:`!13056`

- Using NSEC3 salt is deprecated. ``ee01e77d24c``

  BCP 236 recommends not using salt and iterations. We have been
  disallowing extra iterations for a while now, we will now also
  deprecate salt. :gl:`!13036`

Bug Fixes
~~~~~~~~~

- Fix possible performance issue when issuing rndc commands very
  frequently. ``b1ceaee9f74``

  The :iscman:`rndc` command could get slow if large number of requests
  was made over a short period of time. This has been fixed. :gl:`#3698`
  :gl:`!12967`

- Replace SoftHSMv2 with Kryoptic in the PKCS#11 system tests.
  ``89703fa84ed``

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
  out of space". :gl:`#4695` :gl:`!12929`

- Fix Offline KSK signing when the KSK and a ZSK share a key tag.
  ``321d013627b``

  With dnssec-policy offline-ksk, the KSK and the ZSKs are generated
  separately, so a ZSK can have the same key tag as the KSK. named then
  mistook the ZSK for the KSK when signing the zone: the DNSKEY RRset
  was left without the KSK signature from the imported SKR, or,
  depending on the signing algorithm, importing the SKR failed with a
  "not exact" error. This has been fixed. :gl:`#5540` :gl:`!12917`

- Omit pending data from type-ANY cache responses. ``baddcc46b19``

  When answering a type-ANY query from the cache, data that hasn't been
  validated yet should only be included in the response if the query has
  the CD bit set. :gl:`#5984` :gl:`!13023`

- Rndc accepts stale or mismatched signed responses. ``ea32f5baac7``

  The :iscman:`rndc` command could accept reflected requests as answers.
  Additionally, replayed responses could be accepted. This has been
  fixed. :gl:`#6101` :gl:`!12922`

- Make "rndc -r" work when "rndc" and "named" are from different builds.
  ``a71804862f5``

  Previously :option:`rndc -r` was only guaranteed to display the right
  value when rndc and named were from the same build.  This has been
  fixed. :gl:`#6102` :gl:`!13012`

- DoH client Content-Type validation accepted invalid values.
  ``392cb00d808``

  The Content-Type validation accepted any value that started with
  `application/dns-message`.  This has been fixed. :gl:`#6137`
  :gl:`!12910`

- Send TSIG when NOTIFY is retried over TCP. ``0825aae3a68``

  NOTIFY messages were not TSIG-signed when retried over TCP. This has
  been fixed. :gl:`#6240` :gl:`!12948`

- Try the next server instead of aborting the zone transfer.
  ``95ca5485deb``

  In some cases of a misconfigured primary server, for example, when it
  returned a zone with too many records or a zone that failed
  verification, the zone transfer could get aborted altogether on the
  secondary server instead of trying the next configured primary. This
  has been fixed. :gl:`#6352` :gl:`!13027`

- Automatic interface scanning could stop after a burst of address
  changes. ``690475cb14c``

  When many addresses were removed and added again in quick succession,
  as happens with "netplan apply", the kernel could drop some of the
  resulting interface change notifications. named then gave up on
  automatic interface scanning, logging "automatic interface scanning
  terminated: not enough free resources", and stopped listening on some
  addresses until it was restarted. Lost notifications now trigger a
  fresh scan of the interfaces once the burst is over, and named asks
  the kernel to report only address changes and to queue more of them,
  so that notifications are lost less often in the first place.
  :gl:`#6389` :gl:`!13073`

- DS queries for CNAME names were fetched upstream on every query.
  ``24efa7d5065``

  A resolver answering a DS query for a name that is a CNAME (for
  example www.example.com pointing to example.com) ignored the CNAME it
  had already cached and sent the query upstream every time, so such
  answers were never served from the cache. The cached CNAME is now used
  for DS queries as for any other type, while a DS record or a negative
  DS answer cached at the same name still takes precedence. :gl:`#6455`
  :gl:`!13055`

- Reopening or rolling the dnstap output no longer stalls the server.
  ``1302befabf0``

  Every rndc dnstap -reopen, rndc dnstap -roll and every automatic roll
  of a size-limited dnstap-output file stopped all of named's processing
  until whatever was already running, such as an RPZ zone update, had
  finished and the old output had been flushed, closed and replaced. The
  output is now switched over while the server keeps running; the few
  dnstap messages produced during the switch itself are dropped and
  counted in the dnstap statistics. Logging to a size-limited output
  also no longer checks the file on disk for every message. :gl:`#6461`
  :gl:`!13074`

- Fix ECDHE (forward-secret) cipher suites when building with OpenSSL
  1.0.x. ``e97d015348f``

  SSL_CTX_set_ecdh_auto() (required on OpenSSL 1.0.2 to enable ECDHE) is
  only called for the ephemeral context in isc_tlsctx_createserver(),
  not for contexts loaded from key-file/cert-file. On OpenSSL >= 1.1.0
  ECDHE is on by default and the macro is a no-op, which is why this
  only shows with 1.0.2.

  Call SSL_CTX_set_ecdh_auto(ctx, 1) for every server context.
  :gl:`#6466` :gl:`#6465` :gl:`!12962`

- Align the checkconf root KSK cutoff with named-checkconf.
  ``b8312f2fda8``

  The checkconf system test stopped expecting a warning for a root trust
  anchor containing only the 2026 KSK at 00:00 UTC on 11 October 2026,
  while named-checkconf keeps warning until 23:59 UTC that day, so every
  pipeline failed the test for that one day. The test now uses the same
  cutoff as the checker. :gl:`!12927`

- Fix the UDP receive buffer size for libuv recvmmsg. ``34e4af77cb9``

  libuv splits the UDP receive buffer into UV__UDP_DGRAM_MAXSIZE (64 *
  1024) byte chunks, so a buffer of 20 * UINT16_MAX bytes only holds 19
  chunks and the last datagram slot of every recvmmsg call went unused.
  Size the buffer as 20 * 64 KiB so that all 20 slots are usable.
  :gl:`!12964`

- Update the Extended DNS Error codes. ``be6ee7abe99``

  IANA has registered several new EDE codes since the last time the list
  was updated; we can now display them correctly. :gl:`!12937`


