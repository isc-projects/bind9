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


