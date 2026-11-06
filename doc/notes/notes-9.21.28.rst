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

- Add authoritative support for DELEG.

  Authoritative support for extensible DNS delegation records (DELEG)
  has been implemented, based on the draft in progress at
  https://ietf-wg-deleg.github.io/draft-ietf-deleg-base/draft-ietf-deleg.html.
  DELEG is assigned to type 61440 and DELEGPARAM to type 54.

  If a zone contains a DELEG referral, it is used to answer clients that
  signal their understanding of DELEG records by setting the DE (DELEG
  OK) flag in queries. :option:`dig +deflag` (or ``+de`` for short) can
  be used to set this flag.

  The DELEG specification relaxes the requirement that all zones must
  have an NS RRset at the apex, so :iscman:`named` no longer enforces it
  by default. The new :any:`check-ns` option controls this behavior: the
  allowed values are ``fail``, ``warn``, and ``ignore``, and the default
  is ``warn``. Missing NS records are also no longer fatal in
  :iscman:`named-checkzone`; :option:`named-checkzone -n` with the
  ``fail`` mode restores the old behavior.

  A new flag has been added to DNSKEY records: Authoritative Delegation
  Types (ADT). If this flag is set for any key in the DNSKEY RRset, it
  indicates to a validator that the server implements authoritative
  DELEG: a referral response that does not contain a DELEG record will
  contain a cryptographic proof that the DELEG record does not exist. If
  no ADT-flagged keys are present when signing a zone that contains
  DELEG, a warning is logged. Before any DELEG records are added to a
  zone, an ADT key should be added to the zone, and all authoritative
  servers for the zone must support DELEG.

  Recursive support for DELEG is not implemented yet: the resolver does
  not set the DE flag when sending iterative queries, and DELEG-based
  referrals are not processed. :gl:`!10995`

- Add support for the ML-DSA-44 post-quantum DNSSEC algorithm.

  BIND 9 can now generate keys, sign zones, and validate signatures
  using ML-DSA-44 (DNSSEC algorithm number 18), the post-quantum
  signature scheme specified in ``draft-westerbaan-dnssec-mldsa``. The
  algorithm is available in :iscman:`dnssec-keygen`,
  :iscman:`dnssec-signzone`, and :any:`dnssec-policy` when BIND 9 is
  built against OpenSSL 3.5 or newer. ML-DSA-44 public keys are about
  1.3 KB and signatures about 2.4 KB, so signed responses are
  considerably larger than with the existing algorithms. :gl:`!12769`

- Allow setting the SEP and ADT key flags in :any:`dnssec-policy`.

  The ``keys`` statement in :any:`dnssec-policy` now accepts a
  ``flags`` parameter, which sets the SEP and/or ADT key flags using the
  ``sep`` and ``adt`` keywords. :gl:`#6432`

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate NXDOMAIN redirection.

  The :any:`nxdomain-redirect` option and :any:`type redirect` zones are
  now deprecated. A warning is logged when they are encountered in
  :iscman:`named.conf`. :gl:`#6451`

- Deprecate NSEC3 salt.

  BCP 236 (:rfc:`9276`) recommends using neither extra NSEC3 iterations
  nor salt. Extra iterations have been disallowed for some time; a
  warning is now also logged when :any:`nsec3param` in a
  :any:`dnssec-policy` sets a non-zero ``salt-length``. :gl:`!12755`

Feature Changes
~~~~~~~~~~~~~~~

- Minimize ANY responses over TCP when :any:`minimal-any` is enabled.

  When :any:`minimal-any` was enabled, as it is by default,
  :iscman:`named` minimized ANY responses over UDP but returned all
  available RRsets over TCP. It now returns a single RRset, with its
  covering RRSIGs when requested, and omits unnecessary authority and
  additional data regardless of transport. :gl:`!12581`

- Tighten the syntax of bracketed configuration parameters.

  The syntax of the bracketed parameters of :any:`plugin` and
  :any:`dyndb` statements is now slightly more restrictive: it does not
  distinguish quoted from unquoted text, does not allow bare escaped
  strings, and limits the use of ``include`` within a :any:`plugin`
  statement. :gl:`!12920`

- Require a SubjectAltName in :option:`dig +https` server certificates.

  When verifying the hostname of a DNS-over-HTTPS server,
  :option:`dig +https` accepted a certificate whose only name was in the
  Subject Common Name, while :option:`dig +tls` already required a
  SubjectAltName. OpenSSL 4.1 no longer consults the Common Name, so the
  same certificate was accepted or rejected depending on the OpenSSL
  version. Both options now match the hostname against the
  SubjectAltName only, so a DNS-over-HTTPS server certificate without
  one is rejected with a peer verification failure. :iscman:`named` is
  not affected, as its outgoing TLS connections already enforced this.
  :gl:`!12942`

Bug Fixes
~~~~~~~~~

- Fix a crash when using the :iscman:`synthrecord` plugin.

  An assertion failure could occur when using the :iscman:`synthrecord`
  plugin in conjunction with a truncated answer to a client. This has
  been fixed. :gl:`#6185`

- Fix a crash when dumping zone statistics during zone removal.

  When :option:`rndc stats` dumped per-zone statistics while a zone was
  being removed (for example, by a catalog zone update), :iscman:`named`
  could terminate unexpectedly. This has been fixed. :gl:`#6401`

- Prevent the server from stalling when reopening or rolling the
  :any:`dnstap` output.

  Previously, reopening or rolling the :any:`dnstap-output` file, either
  with :option:`rndc dnstap` or automatically at its size limit, stopped
  all of :iscman:`named`'s processing until whatever was already
  running, such as an RPZ zone update, had finished and the old output
  had been replaced. The output is now switched over while the server
  keeps running; the few :any:`dnstap` messages produced during the
  switch itself are dropped and counted in the :any:`dnstap` statistics.
  Logging to a size-limited output also no longer checks the file on
  disk for every message. :gl:`#6461`

- Prevent automatic interface scanning from stopping after a burst of
  address changes.

  When many addresses were removed and added again in quick succession,
  as happens with ``netplan apply``, the kernel could drop some of the
  resulting interface change notifications. :iscman:`named` then gave up
  on automatic interface scanning, logging ``automatic interface
  scanning terminated: not enough free resources``, and stopped
  listening on some addresses until it was restarted. Lost notifications
  now trigger a fresh scan of the interfaces once the burst is over.
  :iscman:`named` also asks the kernel to report only address changes
  and to queue more of them, so that notifications are lost less often.
  :gl:`#6389`

- Try the next primary server instead of aborting the zone transfer.

  If a misconfigured primary server returned, for example, a zone with
  too many records or a zone that failed verification, the secondary
  server could abort the zone transfer altogether instead of trying the
  next configured primary. This has been fixed. :gl:`#6352`

- Fix Offline KSK signing when the KSK and a ZSK share a key tag.

  With :any:`offline-ksk` in :any:`dnssec-policy`, the KSK and the ZSKs
  are generated separately, so a ZSK can have the same key tag as the
  KSK. :iscman:`named` then mistook the ZSK for the KSK when signing the
  zone; this meant the DNSKEY RRset was left without the KSK signature
  from the imported SKR, or, depending on the signing algorithm, the
  import of the SKR failed with a ``not exact`` error. This has been
  fixed. :gl:`#5540`

- Sign NOTIFY messages retried over TCP with the configured TSIG key.

  When a NOTIFY message to an :any:`also-notify` target with an explicit
  TSIG key failed over UDP and was retried over TCP, the key was lost.
  The retry then used the key from a matching :namedconf:ref:`server`
  statement or, if there was none, was sent unsigned. This has been
  fixed. :gl:`#6240`

- Answer DS queries for CNAME names from the cache.

  Previously, a resolver answering a DS query for a name that was a
  CNAME (for example, ``www.example.com`` pointing to ``example.com``)
  ignored the CNAME it had already cached and sent the query upstream
  every time, so such answers were never served from the cache. The
  cached CNAME is now used for DS queries as it is for any other type,
  while a DS record or a negative DS answer cached at the same name
  still takes precedence. :gl:`#6455`

- Omit unvalidated data from type-ANY cache responses.

  When answering a type-ANY query from the cache, :iscman:`named` could
  include data that had not yet been validated. Such data is now only
  included in the response if the query has the CD bit set. :gl:`#5984`

- Fix incorrect algorithm names for PRIVATEOID-based DNSSEC keys.

  Previously, output that named a key's algorithm, including
  :option:`rndc dnssec -status <rndc dnssec>`, key event log messages,
  and the :iscman:`dnssec-keygen`, :iscman:`dnssec-keyfromlabel`, and
  :iscman:`dnssec-ksr` utilities, displayed the wrong algorithm for keys
  using the PRIVATEOID-based algorithms: the value was truncated and
  shown as a different algorithm or a bare number (for example, ``0``
  instead of ``RSASHA256OID``). The correct algorithm mnemonic is now
  printed in all of these places. :gl:`!12712`

- Fix slow :iscman:`rndc` responses under a high request rate.

  The :iscman:`rndc` command could run slowly if a large number of
  requests was made over a short period of time. This has been fixed.
  :gl:`#3698`

- Prevent :iscman:`rndc` from accepting stale or mismatched signed
  responses.

  The :iscman:`rndc` command could accept reflected requests as answers,
  as well as replayed responses. This has been fixed. :gl:`#6101`

- Make :option:`rndc -r` work when :iscman:`rndc` and :iscman:`named`
  are from different builds.

  Previously, :option:`rndc -r` was only guaranteed to display the
  correct result code when :iscman:`rndc` and :iscman:`named` were from
  the same build. This has been fixed. :gl:`#6102`
