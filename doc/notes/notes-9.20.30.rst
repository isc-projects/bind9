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

Notes for BIND 9.20.30
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Prevent exhaustion of CPU while parsing crafted DNS messages.
  :cve:`2026-19630`

  A crafted message could make :iscman:`named` spend a disproportionate
  amount of time expanding compressed names in it, letting a client
  saturate all worker threads with very little traffic and time out
  legitimate queries. The amount of name expansion a single message can
  require is now bounded, and :iscman:`named` answers FORMERR when that
  bound is exceeded; ordinary traffic, including zone transfers and
  dynamic updates, stays well within it. :gl:`#5932`

- Prevent concurrent GSS-TSIG traffic from terminating :iscman:`named`.
  :cve:`2026-94300`

  A GSS-TSIG session negotiated through TKEY is shared by every message
  signed or verified with that key; previously, :iscman:`named` did not
  serialize access to it, so concurrent signed messages could corrupt
  Kerberos-owned state and terminate :iscman:`named` unexpectedly.
  Access to the shared session is now serialized.

  ISC would like to thank Dave Aitel from OpenAI who independently
  discovered and responsibly reported the issue to ISC. :gl:`#6320`

- Fix a crash with redirect zones and strict QNAME minimization.
  :cve:`2026-96888`

  Processing an NXDOMAIN response with a redirect zone configured could
  cause :iscman:`named` to crash if :any:`qname-minimization` was set to
  ``strict``. This has been fixed.

  ISC would like to thank Vitaly Simonovich for bringing this
  vulnerability to our attention. :gl:`#6386`

- Fix a crash when resuming from a query initiated by RPZ.
  :cve:`2026-97313`

  The :iscman:`named` process could terminate unexpectedly when
  resuming from a query initiated by RPZ processing. This has been
  fixed.

  ISC would like to thank Vitaly Simonovich for bringing this
  vulnerability to our attention. :gl:`#6408`

Bug Fixes
~~~~~~~~~

- Remove a spurious root trust anchor warning and recognize the new
  root key.

  The ``static entry for the root zone WILL FAIL after key rollover``
  warning only makes sense for the IANA root keys, which are rolled over
  using :rfc:`5011`; :iscman:`named` and :iscman:`named-checkconf` no
  longer log it for other static root trust anchors. Both now also warn
  when the configured root :any:`trust-anchors` include an older IANA
  root key but not the new one (ID 38696). :gl:`#5572`

- Do not accept HMAC keys and signatures for SIG(0) or DNSSEC.

  Due to an oversight, keys and signatures using HMAC algorithms, which
  are only meant for TSIG, could be accepted for SIG(0) and DNSSEC
  purposes. This has been fixed. :gl:`#6086`

- Fix DNSSEC tool dates being read one hour late during Daylight Saving
  Time.

  When a key timing value was passed to the DNSSEC tools in the format
  printed by :option:`dnssec-settime -p` (for example,
  ``Wed Jul  1 12:00:00 2026``), it was read as standard time. While
  Daylight Saving Time was in effect, the resulting time was one hour
  late. These values are now read in the correct local time.
  :gl:`#6089`

- Reject URI records with an empty target.

  :rfc:`7553` requires that the target field of a URI record not be
  empty. Such records were accepted, but are now rejected both in zone
  files and in DNS messages. :gl:`#6134`

- Fix a crash when loading a zone in ``raw`` format.

  When loading a specially crafted zone file in ``raw`` format
  (:any:`masterfile-format`), the :iscman:`named` process could
  terminate unexpectedly. This has been fixed. :gl:`#6141`

- Prevent dynamic update prerequisites from probing zones that refuse
  queries.

  Dynamic update prerequisites did not honor :any:`allow-query-on`, nor
  :any:`allow-query` for inline-signed zones, so clients that were
  refused queries could use them to learn whether records existed in the
  zone. These ACLs are now enforced for dynamic updates. :gl:`#6216`
  :gl:`#6217`

- Fix a :iscman:`named-journalprint` crash when using the ``-x``
  option.

  When a journal file had no index table, :iscman:`named-journalprint`
  could crash while printing extended diagnostics with ``-x``. This has
  been fixed. :gl:`#6238`

- Honor :namedconf:ref:`server` settings for keyed NOTIFY and DS
  queries.

  When :iscman:`named` sent a NOTIFY message, or a DS query to a
  parental agent, to a server listed with an explicit TSIG key,
  settings from the matching :namedconf:ref:`server` statement, such as
  :any:`notify-source` or :any:`tcp-only`, could be ignored. This has
  been fixed. :gl:`#6239`

- Fix a catalog zone update bug.

  When a catalog zone update reused the label of an existing member zone
  for a different member zone, the old member zone could remain in the
  view and be served authoritatively until :iscman:`named` was reloaded
  or restarted. This has been fixed. :gl:`#6305`

- Fix an out-of-bounds read in :option:`dig +dns64prefix`.

  When a hostile resolver returned AAAA records of a class other than
  IN, :option:`dig +dns64prefix` could process them and read out of
  bounds. This has been fixed. :gl:`#6312`

- Prevent excessive RRL table scans under load.

  When response rate limiting (:any:`rate-limit`) was in use, recycling
  entries in a large RRL table could require scanning much of the table
  while holding a lock, delaying other responses. The amount of work
  done to recycle entries is now bounded. :gl:`#6351`

- Make :iscman:`named-checkconf` fail on invalid command-line
  arguments.

  Previously, :iscman:`named-checkconf` exited with status 0 when given
  an invalid command-line argument, so a command such as
  ``named-checkconf $ARGS && rndc reload`` could reload the server even
  when ``$ARGS`` was invalid. It now exits with a non-zero status.
  :gl:`#6400`

- Remove the temporary file when saving a zone file fails.

  When writing a zone file failed at the final rename step, the
  temporary file was left behind. It is now removed, as it already was
  on other errors. :gl:`#6405`

- Prevent the statistics channel from serving data on unregistered URL
  prefixes.

  The :any:`statistics-channels` HTTP server also matched request paths
  that were only a prefix of a URL it served, so it returned data for
  URLs that it should have rejected. This has been fixed. :gl:`#6415`

- Fix a crash on OpenBSD when a signal reached an idle worker thread.

  On OpenBSD, a signal delivered to :iscman:`named` while one of its
  worker threads was idle could make the server abort with a fatal
  "Operation canceled" error, because OpenBSD reports such an
  interrupted wait differently from Linux and the other supported
  systems. The wait is now resumed after the signal, as it already was
  elsewhere. :gl:`#6427`

- Resolve names in insecure zones whose apex answers with a CNAME.

  A validating resolver returned SERVFAIL for names in an unsigned zone
  whose apex answers with a CNAME, because the validator refused to look
  up the DS proof showing that the zone was insecure. That lookup is now
  allowed. The cache now also keeps a CNAME alongside other records at
  the same name, including the parent's delegation data, instead of
  replacing one with the other, and chooses the fresher record at lookup
  time. :gl:`#6435`

- Set GSS-TSIG keys to last as long as the negotiated context.

  When GSS-TSIG was in use, the TSIG key that :iscman:`named` derived
  from a completed TKEY negotiation always expired after at most one
  hour, even when the negotiated security context was valid for far
  longer, so clients had to repeat the TKEY exchange every hour to keep
  sending dynamic updates. Such keys are now kept for as long as the
  negotiated context remains valid; the one-hour limit only applies
  when the context lifetime cannot be determined. :gl:`!12783`
