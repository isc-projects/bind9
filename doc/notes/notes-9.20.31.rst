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

Notes for BIND 9.20.31
----------------------

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
  :any:`dnssec-policy` sets a non-zero ``salt-length``. :gl:`!13036`

Feature Changes
~~~~~~~~~~~~~~~

- Minimize ANY responses over TCP when :any:`minimal-any` is enabled.

  When :any:`minimal-any` was enabled, :iscman:`named` minimized ANY
  responses over UDP but returned all available RRsets over TCP. It now
  returns a single RRset, with its covering RRSIGs when requested, and
  omits unnecessary authority and additional data regardless of
  transport. :gl:`!13056`

- Keep accepting CN-only certificates in :option:`dig +https` with
  OpenSSL 4.1.

  When verifying the hostname of a DNS-over-HTTPS server,
  :option:`dig +https` accepts a certificate whose only name is in the
  Subject Common Name. OpenSSL 4.1 no longer consults the Common Name,
  so when BIND 9 was built against it, such certificates were rejected
  with a peer verification failure. :option:`dig +https` now asks
  OpenSSL 4.1 and newer to check the Common Name explicitly, so these
  certificates are accepted as with earlier OpenSSL versions. With
  OpenSSL 4.1 and newer, the Common Name is now also consulted for
  certificates that contain a SubjectAltName. :gl:`!12944`

Bug Fixes
~~~~~~~~~

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
