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

Notes for BIND 9.21.28
----------------------

New Features
~~~~~~~~~~~~

- Add configuration to set key flags SEP and ADT.

  A new parameter to DNSSEC policy ``keys`` has been added to set the
  key flags SEP and/or ADT. :gl:`#6432`

- Add support for the ML-DSA-44 post-quantum DNSSEC algorithm.

  BIND 9 can now generate keys, sign zones, and validate signatures
  using ML-DSA-44 (DNSSEC algorithm number 18), the post-quantum
  signature scheme specified in draft-westerbaan-dnssec-mldsa. The
  algorithm is available in dnssec-keygen, dnssec-signzone, and
  dnssec-policy when BIND 9 is built against OpenSSL 3.5 or newer.
  ML-DSA-44 public keys are about 1.3 KB and signatures about 2.4 KB, so
  signed responses are considerably larger than with the existing
  algorithms.

- Support for authoritative DELEG.

  Implement authoritative support for extensible DNS delegation records
  (DELEG), based on the draft in progress at https://ietf-wg-deleg.githu
  b.io/draft-ietf-deleg-base/draft-ietf-deleg.html.

  DELEG is assigned to type 61440, DELEGPARAM to 54.

  If a zone contains a DELEG referral, it will be used to answer clients
  if they signal their understanding of DELEG records by setting the DE
  (DELEG OK) flag in queries. `dig +deflag` (or `+de` for short) can use
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
  DELEG: if a referral response that does not contain a DELEG record, it
  _will_ contain a cryptographic proof that the DELEG record does not
  exist. If no ADT-flagged keys are present when signing a zone that
  contains DELEG, a warning will be logged. Before any DELEG records are
  added to a zone, an ADT key should be added to the zone, and all
  authoritative servers for the zone must support DELEG.

  Note:  This branch does not implement recursive support for DELEG. The
  resolver does not set the DE flag when sending iterative queries, and
  DELEG-based referrals are not processed. This will be added in later
  work.

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate NXDOMAIN redirection.

  The `nxdomain-redirect` option and `type redirect` zones are now
  deprecated. A warning will be generated when these are encountered in
  `named.conf`.

  Related to #6451

Feature Changes
~~~~~~~~~~~~~~~

- Minimize ANY responses over TCP when minimal-any is enabled.

  When :namedconf:ref:`minimal-any` was enabled, BIND minimized ANY
  responses over UDP but returned all available RRsets over TCP. BIND
  now returns a single RRset, with its covering RRSIGs when requested,
  and omits unnecessary authority and additional data regardless of
  transport.

- Remove bracketed text.

  This commit removes the bracketedtext lexer token type, and replaces
  it with a list of strings. The bracketedtext option made the grammar
  substantially more complex and made several parser optimizations
  impossible.

  The new bracketed tokens category is slightly more restrictive, as it
  doesn't distinguish quoted and unquoted text, does not allow bare
  escaped strings and limits the use of include within a plugin stanza.

- Using NSEC3 salt is deprecated.

  BCP 236 recommends not using salt and iterations. We have been
  disallowing extra iterations for a while now, we will now also
  deprecate salt.

Bug Fixes
~~~~~~~~~

- Fix possible performance issue when issuing rndc commands very
  frequently.

  The :iscman:`rndc` command could get slow if large number of requests
  was made over a short period of time. This has been fixed. :gl:`#3698`

- Fix Offline KSK signing when the KSK and a ZSK share a key tag.

  With dnssec-policy offline-ksk, the KSK and the ZSKs are generated
  separately, so a ZSK can have the same key tag as the KSK. named then
  mistook the ZSK for the KSK when signing the zone: the DNSKEY RRset
  was left without the KSK signature from the imported SKR, or,
  depending on the signing algorithm, importing the SKR failed with a
  "not exact" error. This has been fixed. :gl:`#5540`

- Omit pending data from type-ANY cache responses.

  When answering a type-ANY query from the cache, data that hasn't been
  validated yet should only be included in the response if the query has
  the CD bit set. :gl:`#5984`

- Rndc accepts stale or mismatched signed responses.

  The :iscman:`rndc` command could accept reflected requests as answers.
  Additionally, replayed responses could be accepted. This has been
  fixed. :gl:`#6101`

- Make "rndc -r" work when "rndc" and "named" are from different builds.

  Previously :option:`rndc -r` was only guaranteed to display the right
  value when rndc and named were from the same build.  This has been
  fixed. :gl:`#6102`

- Prevent a crash when using synthrecord.

  An assertion failure could occur when using the `synthrecord` plugin,
  in conjunction with a truncated answer to a client. This is now fixed.
  :gl:`#6185`

- Try the next server instead of aborting the zone transfer.

  In some cases of a misconfigured primary server, for example, when it
  returned a zone with too many records or a zone that failed
  verification, the zone transfer could get aborted altogether on the
  secondary server instead of trying the next configured primary. This
  has been fixed. :gl:`#6352`

- Automatic interface scanning could stop after a burst of address
  changes.

  When many addresses were removed and added again in quick succession,
  as happens with "netplan apply", the kernel could drop some of the
  resulting interface change notifications. named then gave up on
  automatic interface scanning, logging "automatic interface scanning
  terminated: not enough free resources", and stopped listening on some
  addresses until it was restarted. Lost notifications now trigger a
  fresh scan of the interfaces once the burst is over, and named asks
  the kernel to report only address changes and to queue more of them,
  so that notifications are lost less often in the first place.
  :gl:`#6389`

- DS queries for CNAME names were fetched upstream on every query.

  A resolver answering a DS query for a name that is a CNAME (for
  example www.example.com pointing to example.com) ignored the CNAME it
  had already cached and sent the query upstream every time, so such
  answers were never served from the cache. The cached CNAME is now used
  for DS queries as for any other type, while a DS record or a negative
  DS answer cached at the same name still takes precedence. :gl:`#6455`

- Reopening or rolling the dnstap output no longer stalls the server.

  Every rndc dnstap -reopen, rndc dnstap -roll and every automatic roll
  of a size-limited dnstap-output file stopped all of named's processing
  until whatever was already running, such as an RPZ zone update, had
  finished and the old output had been flushed, closed and replaced. The
  output is now switched over while the server keeps running; the few
  dnstap messages produced during the switch itself are dropped and
  counted in the dnstap statistics. Logging to a size-limited output
  also no longer checks the file on disk for every message. :gl:`#6461`

- Wrong algorithm names were shown for PRIVATEOID based DNSSEC keys.

  Output that names a key's algorithm — "rndc dnssec -status", key event
  log messages, and the dnssec-keygen, dnssec-keyfromlabel and
  dnssec-ksr utilities — displayed the wrong algorithm for keys using
  the PRIVATEOID based algorithms: the value was truncated and shown as
  a different algorithm or a bare number (for example "0" instead of
  "RSASHA256OID"). All of these places now print the correct algorithm
  mnemonic.


