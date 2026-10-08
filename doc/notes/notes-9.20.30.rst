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

- [CVE-2026-19630] Crafted DNS messages could exhaust CPU while being
  parsed.

  A crafted message could make named spend a disproportionate amount of
  time expanding compressed names in it, letting a client saturate all
  worker threads with very little traffic and time out legitimate
  queries. named now bounds how much name expansion a single message can
  require and answers FORMERR when that bound is exceeded; ordinary
  traffic, including zone transfers and dynamic updates, stays well
  inside it. :gl:`#5932`

- [CVE-2026-94300] Fix remote termination of named under concurrent
  GSS-TSIG traffic.

  A GSS-TSIG session negotiated through TKEY is shared by every message
  signed or verified with that key, and named did not serialize access
  to it, so concurrent signed messages could corrupt Kerberos-owned
  state and terminate named unexpectedly. :gl:`#6320`

- [CVE-2026-96888] Possible crash with redirect and qname-minimization
  strict.

  Processing an NXDOMAIN response with a redirect zone could cause
  `named` to crash if `qname-minimization` was set to `strict`.
  :gl:`#6386`

- [CVE-2026-97313] Fix a bug when resuming from a query initiated by
  RPZ.

  The :iscman:`named` process could terminate unexpectedly when resuming
  from a query initiated by RPZ processing. This has been fixed.

  ISC would like to thank `whisperer` for reporting the issue.
  :gl:`#6408`

Bug Fixes
~~~~~~~~~

- Remove spurious named/named-checkconf warning.

  "static entry for the root zone WILL FAIL after key rollover - use
  trust-anchors with initial-key or initial-ds instead" only makes sense
  when you are using ICANN root keys as they use RFC 5011 for DNSKEY
  management.  Don't log it in other circumstances. :gl:`#5572`

- Don't accept HMAC-based keys and signatures for SIG(0) or DNSSEC.

  Due to an oversight HMAC keys could be accepted for SIG(0) and DNSSEC
  purposes.  This has been fixed. :gl:`#6086`

- Fix DNSSEC tool dates read one hour late during daylight saving time.

  When a key timing value was passed to the DNSSEC tools in the format
  that dnssec-settime -p prints (for example Wed Jul  1 12:00:00 2026),
  it was read as standard time. While daylight saving time was in
  effect, the resulting time was one hour late. These values are now
  read in the correct local time. :gl:`#6089`

- Enforce non empty URI target field in URI record.

  RFC 7553 requires that the URI target field MUST NOT be an empty URI
  ("").  This is now enforced by the from text and from wire methods.
  :gl:`#6134`

- Fix a space calculation bug when loading a zone in "RAW" format.

  When loading a specially crafted zone file in "RAW" format, the
  :iscman:`named` process could terminate unexpectedly. This has been
  fixed. :gl:`#6141`

- Dynamic update prerequisites could probe zones that refuse queries.

  Dynamic update prerequisites did not honor `allow-query-on`, nor
  `allow-query` for inline-signed zones, so clients that were refused
  queries could use them to learn whether records exist in the zone.
  These ACLs are now enforced for dynamic updates. :gl:`#6216`
  :gl:`#6217`

- Named-journalprint -x could dereference a NULL pointer.

  When a journal is built without an index table, named-journalprint
  could dereference a NULL pointer when printing extended diagnostics
  (-x). This has been fixed. :gl:`#6238`

- Initialise dstip in notify_send_toaddr and checkds_send_toaddr.

  The dstip structure was not initialised on all paths before it was
  used in notify_send_toaddr and checkds_send_toaddr.  This could cause
  server clauses to be ineffective. This has been fixed. :gl:`#6239`

- Fix a catalog zone update bug.

  During a catalog zone update with an unusual case when a new member
  zone appeared in the new version of the catalog zone under the same
  label as used for another member in the old version of the catalog
  zone, the old member zone could remain in the view and be
  authoritatively served until :iscman:`named` was reloaded or
  restarted. This has been fixed. :gl:`#6305`

- Dig +dns64prefix could process non-IN AAAA records.

  dig +dns64prefix could process non-IN AAAA records if there was a
  hostile resolver resulting in an out of bounds read. This has been
  fixed. :gl:`#6312`

- Prevent excessive RRL table scans under load.

  Bound RRL entry recycling to prevent large tables from delaying other
  responses. :gl:`#6351`

- Named-checkconf exits without returning a error with a bad command
  line.

  Named-checkconf was exiting with a 0 exit status when there was a bad
  command line argument.  This meant that `named-checkconf $ARGS &&
  reload` could call reload when $ARGS was bad.  This has been fixed.
  :gl:`#6400`

- Unlink the temporary file on rename failure in
  masterdump.c:closeandrename.

  If the rename fails in masterdump.c:closeandrename there is no useful
  purpose keeping the temporary file. We already remove it on other
  error conditions in that function. :gl:`#6405`

- Statistics channel serves data on unregistered URL prefixes.

  The code to match the requested URL with the URLs named serves wasn't
  correct.  Truncated request URLs where being matched when they
  shouldn't have been.  This has been fixed.  :gl:`#6415`

- Fix a crash on OpenBSD when a signal reaches an idle worker thread.

  On OpenBSD, a signal delivered to named while one of its worker
  threads was idle could make the server abort with a fatal "Operation
  canceled" error, because OpenBSD reports such an interrupted wait
  differently from Linux and the other supported systems. The wait is
  now resumed after the signal, as it already was elsewhere. :gl:`#6427`

- Resolve names in insecure zones whose apex answers with a CNAME.

  A validating resolver returned SERVFAIL for names in an unsigned zone
  whose apex answers with a CNAME, because the validator refused to look
  up the DS proof that shows the zone is insecure. That lookup is now
  allowed, and the cache keeps a CNAME next to other records at the same
  name (including the parent's delegation data) instead of deleting one
  for the other, choosing the fresher record at lookup time; this
  supersedes the earlier fix for stale answers after a record changes to
  or from a CNAME. :gl:`#6435`

- GSS-TSIG keys now last as long as the negotiated context.

  When GSS-TSIG is in use, the TSIG key that named derives from a
  completed TKEY negotiation always expired after at most one hour, even
  when the negotiated security context was valid for far longer, so
  clients had to repeat the TKEY exchange every hour to keep sending
  dynamic updates. named now keeps such a key for as long as that
  context remains valid, and applies the one-hour limit only when its
  lifetime cannot be determined.


