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

BIND 9.20.30
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-19630] Crafted DNS messages could exhaust CPU while being
  parsed. ``5e8a2e1c76a``

  A crafted message could make named spend a disproportionate amount of
  time expanding compressed names in it, letting a client saturate all
  worker threads with very little traffic and time out legitimate
  queries. named now bounds how much name expansion a single message can
  require and answers FORMERR when that bound is exceeded; ordinary
  traffic, including zone transfers and dynamic updates, stays well
  inside it. :gl:`#5932`

- [CVE-2026-94300] Fix remote termination of named under concurrent
  GSS-TSIG traffic. ``fe9cc14af0d``

  A GSS-TSIG session negotiated through TKEY is shared by every message
  signed or verified with that key, and named did not serialize access
  to it, so concurrent signed messages could corrupt Kerberos-owned
  state and terminate named unexpectedly. :gl:`#6320`

- [CVE-2026-96888] Possible crash with redirect and qname-minimization
  strict. ``1e1d0d42b59``

  Processing an NXDOMAIN response with a redirect zone could cause
  `named` to crash if `qname-minimization` was set to `strict`.
  :gl:`#6386`

- [CVE-2026-97313] Fix a bug when resuming from a query initiated by
  RPZ. ``3e4fe14392e``

  The :iscman:`named` process could terminate unexpectedly when resuming
  from a query initiated by RPZ processing. This has been fixed.

  ISC would like to thank `whisperer` for reporting the issue.
  :gl:`#6408`

Bug Fixes
~~~~~~~~~

- Remove spurious named/named-checkconf warning. ``b066dde7047``

  "static entry for the root zone WILL FAIL after key rollover - use
  trust-anchors with initial-key or initial-ds instead" only makes sense
  when you are using ICANN root keys as they use RFC 5011 for DNSKEY
  management.  Don't log it in other circumstances. :gl:`#5572`
  :gl:`!12788`

- Fix a data race in the RPZ summary database. ``f892fe7857b``

  Reloading a response policy zone could modify entries of the summary
  database in place while queries were reading them without a lock,
  which ThreadSanitizer reported as a data race. Entries are now
  replaced with a fresh copy instead, so queries keep reading a
  consistent entry and the query path stays lock-free. :gl:`#5594`
  :gl:`!12696`

- Fix private-type RRset handling during apex delete updates.
  ``f0aa2a0fab3``

  When DNS UPDATE processing manipulates `diff.tuples` (e.g. during
  delete-all-at-name or delete-RRset operations at a zone apex with
  TYPE65534 private signing state), tuples were being unlinked from the
  list using `ISC_LIST_UNLINK()` directly. This bypassed the `diff.size`
  counter, causing it to drift out of sync with the actual list
  contents.

  This commit introduces `dns_diff_unlink()`, which keeps `diff.size`
  accurate when removing a tuple, and updates all call sites in
  `lib/dns/` and `lib/ns/` that previously manipulated the list
  directly.

  ISC thanks Mcsky23 and Qifan Zhang of Palo Alto Networks for reporting
  the issue. :gl:`#5802` :gl:`!12703`

- Revert "Prevent overwriting an existing iptable node when merging"
  ``12dda38637f``

  This reverts commit ebd86076bc30322d2955599bbc36ecfcbf8c0664.

  The above change had unintended side effects.  The issue it attempted
  to address will be fixed properly in due course. :gl:`#6049`
  :gl:`!12740`

- Don't accept HMAC-based keys and signatures for SIG(0) or DNSSEC.
  ``52326a3fd05``

  Due to an oversight HMAC keys could be accepted for SIG(0) and DNSSEC
  purposes.  This has been fixed. :gl:`#6086` :gl:`!12700`

- Fix DNSSEC tool dates read one hour late during daylight saving time.
  ``78be42b3fdd``

  When a key timing value was passed to the DNSSEC tools in the format
  that dnssec-settime -p prints (for example Wed Jul  1 12:00:00 2026),
  it was read as standard time. While daylight saving time was in
  effect, the resulting time was one hour late. These values are now
  read in the correct local time. :gl:`#6089` :gl:`!12889`

- "libisccc flat S-expression free can exhaust stack" ``bcb45f4c696``

  It was possible to exceed the stack in rndc if it had to free really
  deep answer chains from a hostile server.  Flatten the freeing of
  answer chains.  Printing the sexpr tree for debugging also suffers
  from the same stack exhaustion problem due to excessive recursion.
  Flatten sexpr tree printing. :gl:`#6090` :gl:`!12786`

- Fix RRL qps-scale TCP credit age check uses the response bucket age.
  ``0f047525d94``

  There was a cut-and-paste bug in `debit_rrl_entry` where the age from
  the wrong entry was used to set scale.  Use `credit_e` instead of `e`.
  :gl:`#6106` :gl:`!12850`

- Enforce non empty URI target field in URI record. ``409b4c82e19``

  RFC 7553 requires that the URI target field MUST NOT be an empty URI
  ("").  This is now enforced by the from text and from wire methods.
  :gl:`#6134` :gl:`!12699`

- Fix a space calculation bug when loading a zone in "RAW" format.
  ``f6a08c7f34e``

  When loading a specially crafted zone file in "RAW" format, the
  :iscman:`named` process could terminate unexpectedly. This has been
  fixed. :gl:`#6141` :gl:`!12782`

- Dst_key_fromdns should fail on unsupported algorithms. ``ce7c7704f30``

  dst_key_fromdns could succeed on unsupported algorithms causing
  failures later in code which assumed that a dst_key_t always had a
  supported algorithms.   :gl:`#6192` :gl:`!12707`

- Dynamic update prerequisites could probe zones that refuse queries.
  ``0421a637880``

  Dynamic update prerequisites did not honor `allow-query-on`, nor
  `allow-query` for inline-signed zones, so clients that were refused
  queries could use them to learn whether records exist in the zone.
  These ACLs are now enforced for dynamic updates. :gl:`#6216`
  :gl:`#6217` :gl:`!12905`

- Fix delv +ns view reference counting. ``109c80c74e9``

  Delv's matchview doesn't attach to the view as named does when called
  with +ns. This can result in a view reference underflow if an
  unexpected request is received by delv.  This has been fixed.
  :gl:`#6236` :gl:`!12737`

- Named-journalprint -x could dereference a NULL pointer.
  ``26f87b37a26``

  When a journal is built without an index table, named-journalprint
  could dereference a NULL pointer when printing extended diagnostics
  (-x). This has been fixed. :gl:`#6238` :gl:`!12721`

- Initialise dstip in notify_send_toaddr and checkds_send_toaddr.
  ``3260bf7b513``

  The dstip structure was not initialised on all paths before it was
  used in notify_send_toaddr and checkds_send_toaddr.  This could cause
  server clauses to be ineffective. This has been fixed. :gl:`#6239`
  :gl:`!12722`

- Fix a catalog zone update bug. ``a694601fafe``

  During a catalog zone update with an unusual case when a new member
  zone appeared in the new version of the catalog zone under the same
  label as used for another member in the old version of the catalog
  zone, the old member zone could remain in the view and be
  authoritatively served until :iscman:`named` was reloaded or
  restarted. This has been fixed. :gl:`#6305` :gl:`!12751`

- Fix empty SSLKEYLOGFILE environment variable handling. ``da53d3097d3``

  If named is started with an empty SSLKEYLOGFILE environment variable
  it could trigger a REQUIRE failure.  Treat an empty SSLKEYLOGFILE
  environment variable as if it doesn't exist. :gl:`#6306` :gl:`!12873`

- Dig +dns64prefix could process non-IN AAAA records. ``8a05bd1db04``

  dig +dns64prefix could process non-IN AAAA records if there was a
  hostile resolver resulting in an out of bounds read. This has been
  fixed. :gl:`#6312` :gl:`!12793`

- Save_command_line mishandles byte with high bit set. ``fe35e694536``

  save_command_line fails to handle char with high bit set correctly
  when char is treated as signed.  This has been fixed. :gl:`#6316`
  :gl:`!12720`

- Account for null terminator when using NAME_MAX. ``2230c781761``

  The `NAME_MAX` value in `limits.h` is not guaranteed to include space
  for the terminating null character in a string. This can cause
  unexpected behavior on some platforms, such as a directory scan
  stopping too soon if a 255-character filename is encountered.

  Buffers intended to hold filenames are now allocated with `NAME_MAX +
  1` bytes. :gl:`#6324` :gl:`!12903`

- Prevent excessive RRL table scans under load. ``76afd2b2b65``

  Bound RRL entry recycling to prevent large tables from delaying other
  responses. :gl:`#6351` :gl:`!12794`

- Named-checkconf exits without returning a error with a bad command
  line. ``f187d92dde7``

  Named-checkconf was exiting with a 0 exit status when there was a bad
  command line argument.  This meant that `named-checkconf $ARGS &&
  reload` could call reload when $ARGS was bad.  This has been fixed.
  :gl:`#6400` :gl:`!12727`

- Unlink the temporary file on rename failure in
  masterdump.c:closeandrename. ``9fd230d7e06``

  If the rename fails in masterdump.c:closeandrename there is no useful
  purpose keeping the temporary file. We already remove it on other
  error conditions in that function. :gl:`#6405` :gl:`!12741`

- Statistics channel serves data on unregistered URL prefixes.
  ``89ad99d551d``

  The code to match the requested URL with the URLs named serves wasn't
  correct.  Truncated request URLs where being matched when they
  shouldn't have been.  This has been fixed.  :gl:`#6415` :gl:`!12789`

- Fix a crash on OpenBSD when a signal reaches an idle worker thread.
  ``2e7855b1577``

  On OpenBSD, a signal delivered to named while one of its worker
  threads was idle could make the server abort with a fatal "Operation
  canceled" error, because OpenBSD reports such an interrupted wait
  differently from Linux and the other supported systems. The wait is
  now resumed after the signal, as it already was elsewhere. :gl:`#6427`
  :gl:`!12771`

- Resolve names in insecure zones whose apex answers with a CNAME.
  ``ffa1efabddb``

  A validating resolver returned SERVFAIL for names in an unsigned zone
  whose apex answers with a CNAME, because the validator refused to look
  up the DS proof that shows the zone is insecure. That lookup is now
  allowed, and the cache keeps a CNAME next to other records at the same
  name (including the parent's delegation data) instead of deleting one
  for the other, choosing the fresher record at lookup time; this
  supersedes the earlier fix for stale answers after a record changes to
  or from a CNAME. :gl:`#6435` :gl:`!12890`

- Add sign delay to offline KSK ZRRSIG state timing. ``6a4acfe5a43``

  With offline KSK, the ZRRSIG state of a ZSK was derived from the key
  timing without the sign delay, and retire-safety only counted towards
  the next rekey time, so during a ZSK rollover the signatures were
  reported omnipresent (or hidden) days too early. Signing itself is not
  affected. :gl:`!12863`

- Fix TSIG session loss across a reload. ``5b63fff3efc``

  Dynamic TSIG sessions negotiated through TKEY were saved to disk by
  whichever view released the key ring first, which during a reload was
  the outgoing view — consuming sessions the incoming view was still
  using and forcing clients to renegotiate. Sessions are now saved only
  when the last view releases them, and a failed save no longer replaces
  the stored sessions with a truncated file. :gl:`!12802`

- GSS-TSIG keys now last as long as the negotiated context.
  ``c9af511a867``

  When GSS-TSIG is in use, the TSIG key that named derives from a
  completed TKEY negotiation always expired after at most one hour, even
  when the negotiated security context was valid for far longer, so
  clients had to repeat the TKEY exchange every hour to keep sending
  dynamic updates. named now keeps such a key for as long as that
  context remains valid, and applies the one-hour limit only when its
  lifetime cannot be determined. :gl:`!12783`

- Keep the zone table read section open until the zone is attached.
  ``5f35fd6c5c5``

  dns_zt_find() ended its qp-trie read transaction before checking the
  zone type and attaching to the zone, which is only safe as long as the
  callers in view.c happen to hold an RCU read lock of their own. The
  read section is now closed after the reference has been taken, so the
  zone can no longer be reclaimed out from under the lookup.
  :gl:`!12780`

- Pass the message pools to destroypools() in the declared order.
  ``23aef824bfb``

  The arguments were swapped, so the emptiness assertion named the wrong
  pool. :gl:`!12814`

- Support program suffixes of tsig-keygen and ddns-confgen.
  ``b2cd0c5d0a7``

  Suffixes different than .exe are used on Fedora. But those commands
  require exact names only. Allow switching between two variants only
  from prefix. That should work on all platforms. It should support also
  names like tsig-keygen-9.18 or tsig-keygen-9.21.

  The same case applies to named-checkzone and named-compilezone.
  :gl:`!12901`


