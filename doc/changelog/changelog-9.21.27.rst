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

BIND 9.21.27
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-19630] Crafted DNS messages could exhaust CPU while being
  parsed. ``6b80ca9b191``

  A crafted message could make named spend a disproportionate amount of
  time expanding compressed names in it, letting a client saturate all
  worker threads with very little traffic and time out legitimate
  queries. named now bounds how much name expansion a single message can
  require and answers FORMERR when that bound is exceeded; ordinary
  traffic, including zone transfers and dynamic updates, stays well
  inside it. :gl:`#5932`

- [CVE-2026-94300] Fix remote termination of named under concurrent
  GSS-TSIG traffic. ``0fd028e16d9``

  A GSS-TSIG session negotiated through TKEY is shared by every message
  signed or verified with that key, and named did not serialize access
  to it, so concurrent signed messages could corrupt Kerberos-owned
  state and terminate named unexpectedly. :gl:`#6320`

- [CVE-2026-96888] Possible crash with redirect and qname-minimization
  strict. ``13fe8e97f81``

  Processing an NXDOMAIN response with a redirect zone could cause
  `named` to crash if `qname-minimization` was set to `strict`.
  :gl:`#6386`

- [CVE-2026-97313] Fix a bug when resuming from a query initiated by
  RPZ. ``34dfbc25b9b``

  The :iscman:`named` process could terminate unexpectedly when resuming
  from a query initiated by RPZ processing. This has been fixed.

  ISC would like to thank `whisperer` for reporting the issue.
  :gl:`#6408`

New Features
~~~~~~~~~~~~

- Add NXNAME to the known type mnemonics. ``c0a3e676641``

  Type `NXNAME` is used by servers returning Compact Denial of Existence
  in DNSSEC (RFC 9824) answers.  Such answers will now be displayed
  using the `NXNAME` mnemonic instead of `TYPE128`. :gl:`#5721`
  :gl:`!11500`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the authors.bind builtin zone. ``89d23d1791a``

  The authors.bind chaos zone contained a static, hand-maintained list
  of contributors that has become outdated and incomplete.  Now that the
  project uses version control which tracks all contributions (including
  external ones), the zone serves no useful purpose.

  Remove the authors_lookup() function, the associated zone definition
  from the default configuration, and the corresponding documentation.
  :gl:`#5417` :gl:`!11068`

Feature Changes
~~~~~~~~~~~~~~~

- Reject DNS messages that repeat a SOA, CNAME, or DNAME record.
  ``a04770e52ac``

  A DNS message could carry the same SOA, CNAME, or DNAME record many
  times and named kept every copy while parsing it; with name
  compression those copies took up far more memory internally than in
  the message itself, and every later processing step had to handle all
  of them. named now treats a message that repeats such a record as
  malformed, whether or not the copies are identical, so responses from
  a server that sends duplicate singleton records are rejected instead
  of being accepted as before. :gl:`#6335` :gl:`!12803`

- Use `size_t` as the type used for `isc_counter_t` ``73fe702d39a``

  `isc_counter_t` was using a plethora of integer types internally and
  in it's API. Change it to be consistent and use `size_t` only.
  :gl:`#6354` :gl:`!12702`

- Do not store the effective config as text. ``2534fd5371b``

  In the 1m zones startup test in perflab, storing the effective config
  as text brings us from 45.3s to 56s startup (and should have a similar
  effect on `rndc reload` and `rndc reconfig`), while saving us 1.7 GB
  of memory. It has been easier to reduce memory consumption than
  startup time, so we'd rather take the startup time side of the
  tradeoff. :gl:`!12732`

- Optimize NSEC3 parsing and query handling. ``09565537725``

  This branch introduces a more specialized base32 conversion of NSEC3
  hashes, and optimizes the loading of NSEC3 records from zone files.
  :gl:`!12733`

- Reject compressed names in record types that forbid compression.
  ``cf682cf0a18``

  named used to accept compressed domain names inside any type of DNS
  record, but RFC 3597 permits compression only in the types defined in
  RFC 1035 and in a few older types such as SRV and NAPTR. named now
  rejects as malformed any DNS message that compresses a name in another
  record type, for example the signer name in an RRSIG record.
  :gl:`!12854`

- Simplify dns_rdata_tostruct() and remove dns_rdata_freestruct()
  ``22dcc479f6e``

  The type-specific rdata structures could optionally own copies of
  their data, but nearly every caller used the borrowing mode and the
  few that did not had no need for a private copy. The memory-context
  argument, the per-structure mctx member, and the whole
  dns_rdata_freestruct() machinery are removed, so the structures now
  always point directly into the wire-format rdata and the caller keeps
  that rdata alive while the structure is in use. :gl:`!12757`

- Skip expensive string lookups in zone creation in the common case.
  ``74c478f8fcf``

  Both the search for rfc1918 names and for zone template labels are
  implemented in linear time in the number of possible cases. In
  hosting-type setups with lots of zones, these checks can delay startup
  time. This MR adds a pre-check to skip the expensive checks when
  possible. :gl:`!11070`

Bug Fixes
~~~~~~~~~

- Remove spurious named/named-checkconf warning. ``89df45ac94b``

  "static entry for the root zone WILL FAIL after key rollover - use
  trust-anchors with initial-key or initial-ds instead" only makes sense
  when you are using ICANN root keys as they use RFC 5011 for DNSKEY
  management.  Don't log it in other circumstances. :gl:`#5572`
  :gl:`!11097`

- Fix a data race in the RPZ summary database. ``c53102aed05``

  Reloading a response policy zone could modify entries of the summary
  database in place while queries were reading them without a lock,
  which ThreadSanitizer reported as a data race. Entries are now
  replaced with a fresh copy instead, so queries keep reading a
  consistent entry and the query path stays lock-free. :gl:`#5594`
  :gl:`!12630`

- Fix private-type RRset handling during apex delete updates.
  ``2b5dfa831d6``

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
  the issue. :gl:`#5802` :gl:`!12170`

- Revert "Prevent overwriting an existing iptable node when merging"
  ``b0e59d9a336``

  This reverts commit b1ee26c94d9c8084d3e40a5f190ef5cc33abca99.

  The above change had unintended side effects.  The issue it attempted
  to address will be fixed properly in due course. :gl:`#6049`
  :gl:`!12738`

- Dns_ds_fromkeyrdata private OID digest length check is off by one.
  ``0e902459393``

  The length check in dns_ds_fromkeyrdata for private OID digest check
  failed to account for the length byte itself.  This has been fixed.
  :gl:`#6079` :gl:`!12784`

- Don't accept HMAC-based keys and signatures for SIG(0) or DNSSEC.
  ``285e09588d0``

  Due to an oversight HMAC keys could be accepted for SIG(0) and DNSSEC
  purposes.  This has been fixed. :gl:`#6086` :gl:`!12237`

- Fix DNSSEC tool dates read one hour late during daylight saving time.
  ``ff2504bbb58``

  When a key timing value was passed to the DNSSEC tools in the format
  that dnssec-settime -p prints (for example Wed Jul  1 12:00:00 2026),
  it was read as standard time. While daylight saving time was in
  effect, the resulting time was one hour late. These values are now
  read in the correct local time. :gl:`#6089` :gl:`!12857`

- "libisccc flat S-expression free can exhaust stack" ``9403ddeaa5d``

  It was possible to exceed the stack in rndc if it had to free really
  deep answer chains from a hostile server.  Flatten the freeing of
  answer chains.  Printing the sexpr tree for debugging also suffers
  from the same stack exhaustion problem due to excessive recursion.
  Flatten sexpr tree printing. :gl:`#6090` :gl:`!12572`

- Fix RRL qps-scale TCP credit age check uses the response bucket age.
  ``129afe4ef2e``

  There was a cut-and-paste bug in `debit_rrl_entry` where the age from
  the wrong entry was used to set scale.  Use `credit_e` instead of `e`.
  :gl:`#6106` :gl:`!12848`

- Enforce non empty URI target field in URI record. ``7fe5d97d7ce``

  RFC 7553 requires that the URI target field MUST NOT be an empty URI
  ("").  This is now enforced by the from text and from wire methods.
  :gl:`#6134` :gl:`!12631`

- Fix a space calculation bug when loading a zone in "RAW" format.
  ``dd8f60f7fcc``

  When loading a specially crafted zone file in "RAW" format, the
  :iscman:`named` process could terminate unexpectedly. This has been
  fixed. :gl:`#6141` :gl:`!12508`

- Dst_key_fromdns should fail on unsupported algorithms. ``d9e14117c68``

  dst_key_fromdns could succeed on unsupported algorithms causing
  failures later in code which assumed that a dst_key_t always had a
  supported algorithms.   :gl:`#6192` :gl:`!12598`

- Fix isc_time_formatISO8601TZms writes past short caller buffers.
  ``07887ddd5da``

  The function isc_time_formatiso8601tzms was incorrectly documented and
  if the passed in buffer was exactly 29 bytes long there was a 1 byte
  buffer write overrun.  This has been fixed.  :gl:`#6199` :gl:`!12680`

- Fix regression in dns_nsec3_activex. ``4246025b596``

  When DNS_RDATASET_FOREACH was added there was a regression introduced
  into dns_nsec3_activex, the answer was unconditionally set to false,
  if complete was true or if the private type was set to 0.   This has
  been fixed. :gl:`#6201` :gl:`!12709`

- Rndc signing returned the wrong name for private algorithms.
  ``beec9b4408e``

  The wrong function was called when converting the algorithm number to
  a names for "rndc signing". This has been fixed. :gl:`#6206`
  :gl:`!12618`

- Dynamic update prerequisites could probe zones that refuse queries.
  ``784d6664ce3``

  Dynamic update prerequisites did not honor `allow-query-on`, nor
  `allow-query` for inline-signed zones, so clients that were refused
  queries could use them to learn whether records exist in the zone.
  These ACLs are now enforced for dynamic updates. :gl:`#6216`
  :gl:`#6217` :gl:`!12878`

- Fix delv +ns view reference counting. ``74f9e3a4fe6``

  Delv's matchview doesn't attach to the view as named does when called
  with +ns. This can result in a view reference underflow if an
  unexpected request is received by delv.  This has been fixed.
  :gl:`#6236` :gl:`!12723`

- Named-journalprint -x could dereference a NULL pointer.
  ``0e3a973d09b``

  When a journal is built without an index table, named-journalprint
  could dereference a NULL pointer when printing extended diagnostics
  (-x). This has been fixed. :gl:`#6238` :gl:`!12713`

- Initialise dstip in notify_send_toaddr and checkds_send_toaddr.
  ``f48a8806f8a``

  The dstip structure was not initialised on all paths before it was
  used in notify_send_toaddr and checkds_send_toaddr.  This could cause
  server clauses to be ineffective. This has been fixed. :gl:`#6239`
  :gl:`!12714`

- Set the in rsa exponent bounds to null after shutdown. ``c051e08f152``

  `dst__opensslrsa_shutdown` frees the resources consumed by the BIGNUMs
  used for checking RSA exponent bounds but does not set the pointers to
  `NULL`.

  This is not a real issue since there is no possible codepath that can
  deinitialize and initialize libdns. Nonetheless, set the freed
  resources to NULL for consistency with the rest of the codebase.
  :gl:`#6258` :gl:`!12808`

- Restore only previously scheduled headers on rollback. ``2bd94b111a3``

  Record a header for rollback only when it was successfully removed
  from the resign heap. This prevents rollback from inserting ordinary,
  unscheduled headers into the heap. :gl:`#6303` :gl:`!12600`

- Fix a catalog zone update bug. ``16d5188a629``

  During a catalog zone update with an unusual case when a new member
  zone appeared in the new version of the catalog zone under the same
  label as used for another member in the old version of the catalog
  zone, the old member zone could remain in the view and be
  authoritatively served until :iscman:`named` was reloaded or
  restarted. This has been fixed. :gl:`#6305` :gl:`!12599`

- Fix empty SSLKEYLOGFILE environment variable handling. ``6755ca4fe2e``

  If named is started with an empty SSLKEYLOGFILE environment variable
  it could trigger a REQUIRE failure.  Treat an empty SSLKEYLOGFILE
  environment variable as if it doesn't exist. :gl:`#6306` :gl:`!12724`

- Dig +dns64prefix could process non-IN AAAA records. ``97e33db5532``

  dig +dns64prefix could process non-IN AAAA records if there was a
  hostile resolver resulting in an out of bounds read. This has been
  fixed. :gl:`#6312` :gl:`!12708`

- Save_command_line mishandles byte with high bit set. ``f861f65250c``

  save_command_line fails to handle char with high bit set correctly
  when char is treated as signed.  This has been fixed. :gl:`#6316`
  :gl:`!12716`

- Account for null terminator when using NAME_MAX. ``68a55791ca9``

  The `NAME_MAX` value in `limits.h` is not guaranteed to include space
  for the terminating `'\0'` character in a string. This can cause
  unexpected behavior on some platforms, such as a directory scan
  stopping too soon if a 255-character filename is encountered.

  Buffers intended to hold filenames are now allocated with `NAME_MAX +
  1` bytes. :gl:`#6324` :gl:`!12897`

- Prevent excessive RRL table scans under load. ``411645db19e``

  Bound RRL entry recycling to prevent large tables from delaying other
  responses. :gl:`#6351` :gl:`!12602`

- Fix a crash when receiving an answer with a referra from a `forward
  only` forwarder. ``8d3ac3c2bf9``

  The resolver could crash when a forwarder configured with `forward
  only` answered a query with a referral. This is now fixed. :gl:`#6373`
  :gl:`!12657`

- Named-checkconf exits without returning a error with a bad command
  line. ``2d2a4e1fbb1``

  Named-checkconf was exiting with a 0 exit status when there was a bad
  command line argument.  This meant that `named-checkconf $ARGS &&
  reload` could call reload when $ARGS was bad.  This has been fixed.
  :gl:`#6400` :gl:`!12715`

- Unlink the temporary file on rename failure in
  masterdump.c:closeandrename. ``f9187e7d99e``

  If the rename fails in masterdump.c:closeandrename there is no useful
  purpose keeping the temporary file. We already remove it on other
  error conditions in that function. :gl:`#6405` :gl:`!12729`

- Statistics channel serves data on unregistered URL prefixes.
  ``35d7699e226``

  The code to match the requested URL with the URLs named serves wasn't
  correct.  Truncated request URLs where being matched when they
  shouldn't have been.  This has been fixed.  :gl:`#6415` :gl:`!12742`

- Fix a crash on OpenBSD when a signal reaches an idle worker thread.
  ``1347f5e91ae``

  On OpenBSD, a signal delivered to named while one of its worker
  threads was idle could make the server abort with a fatal "Operation
  canceled" error, because OpenBSD reports such an interrupted wait
  differently from Linux and the other supported systems. The wait is
  now resumed after the signal, as it already was elsewhere. :gl:`#6427`
  :gl:`!12766`

- BIND erroneously used SOA for NOTIFY(CDS) ``6d416c35824``

  When notifying the end point of a DSYNC record, BIND was still using
  SOA as the type instead of CDS. This has been fixed. :gl:`#6433`
  :gl:`!12872`

- Resolve names in insecure zones whose apex answers with a CNAME.
  ``6a9fa41ca5d``

  A validating resolver returned SERVFAIL for names in an unsigned zone
  whose apex answers with a CNAME, because the validator refused to look
  up the DS proof that shows the zone is insecure. That lookup is now
  allowed, and the cache keeps a CNAME next to other records at the same
  name (including the parent's delegation data) instead of deleting one
  for the other, choosing the fresher record at lookup time; this
  supersedes the earlier fix for stale answers after a record changes to
  or from a CNAME. :gl:`#6435` :gl:`!12838`

- Accept compressed names in the types RFC 3597 lists. ``c9b1feca99d``

  RFC 3597 section 4 asks receivers to decompress names in RP, AFSDB,
  RT, SIG, PX, NXT, NAPTR and SRV. named's behavior doesn't change,
  because message parsing already decompresses every type. :gl:`!12853`

- Add sign delay to offline KSK ZRRSIG state timing. ``a8eb03d8592``

  With offline KSK, the ZRRSIG state of a ZSK was derived from the key
  timing without the sign delay, and retire-safety only counted towards
  the next rekey time, so during a ZSK rollover the signatures were
  reported omnipresent (or hidden) days too early. Signing itself is not
  affected. :gl:`!12762`

- Cache hostname, version, and server-id at configuration time.
  ``4568504e9c2``

  Replace the pattern of calling gethostname() on every CHAOS TXT query
  and every NSID EDNS option with a cached copy that is computed once
  during configuration loading and updated on reconfiguration.

  The char* + bool sentinel pairs (version/version_set,
  hostname/hostname_set, server_id/usehostname) are consolidated into
  isc_region_t structs, which carry both the pointer and length,
  eliminating redundant strlen() calls in the query path and simplifying
  the control flow in builtin.c and client.c.

  This reduces per-query overhead for hostname.bind, version.bind,
  id.server lookups and NSID option generation. :gl:`!11635`

- Decompress message names into their own buffers. ``ed0a44bcac6``

  Names returned by dns_message_gettempname() are dns_fixedname_t
  objects, each with a buffer large enough for any name. Despite that,
  the message parser decompressed question and owner names into the
  shared scratchpad buffer. Names are now decompressed directly into
  their own buffers, so only rdata uses the scratchpad and large
  messages allocate fewer extra scratchpad buffers. :gl:`!12891`

- Fix TSIG session loss across a reload. ``375c8f5243c``

  Dynamic TSIG sessions negotiated through TKEY were saved to disk by
  whichever view released the key ring first, which during a reload was
  the outgoing view — consuming sessions the incoming view was still
  using and forcing clients to renegotiate. Sessions are now saved only
  when the last view releases them, and a failed save no longer replaces
  the stored sessions with a truncated file. :gl:`!12800`

- Fix and extend the counted_by bounds annotations. ``b7166490fbb``

  More structs now carry counted_by annotations, and the existing ones
  were reordered so the length comes before the pointer it describes.
  :gl:`!12804`

- Fix compression table bookkeeping in dns_compress_rollback()
  ``a39b1ce9596``

  Discarding the whole compression table underflowed its entry count, so
  the rest of the message went out uncompressed, and a partial rollback
  could miss entries that were moved during deletion. Both only made
  responses less compact; named never sent a wrong name. :gl:`!12855`

- Fix test_client and test_server. ``4f1dd1b54ac``

  test_client and test_server were broken due to using netmgr without
  starting loopmgr. :gl:`!12541`

- GSS-TSIG keys now last as long as the negotiated context.
  ``21e44102bf0``

  When GSS-TSIG is in use, the TSIG key that named derives from a
  completed TKEY negotiation always expired after at most one hour, even
  when the negotiated security context was valid for far longer, so
  clients had to repeat the TKEY exchange every hour to keep sending
  dynamic updates. named now keeps such a key for as long as that
  context remains valid, and applies the one-hour limit only when its
  lifetime cannot be determined. :gl:`!12749`

- Keep the zone table read section open until the zone is attached.
  ``89fa3e48577``

  dns_zt_find() ended its qp-trie read transaction before checking the
  zone type and attaching to the zone, which is only safe as long as the
  callers in view.c happen to hold an RCU read lock of their own. The
  read section is now closed after the reference has been taken, so the
  zone can no longer be reclaimed out from under the lookup.
  :gl:`!12778`

- Memory leak when answering ANY queries for a wildcard name.
  ``e561c50b219``

  Answering an ANY query with DNSSEC requested, for a name matched by a
  wildcard, leaked memory. This regression was introduced in 9.21.25.
  :gl:`!12812`

- Pass the message pools to destroypools() in the declared order.
  ``08f5eb04025``

  The arguments were swapped, so the emptiness assertion named the wrong
  pool. :gl:`!12813`

- Release response-policy zone memory as soon as a reload finishes.
  ``74e2cbdf99a``

  The response-policy zone database is only written while a policy zone
  is being reloaded, so memory left over from one reload could stay
  allocated until the next one — indefinitely for a policy zone that is
  never updated again. named now reclaims it before each reloaded policy
  takes effect. :gl:`!12779`

- Support program suffixes of tsig-keygen and ddns-confgen.
  ``99ee1426f92``

  Suffixes different than .exe are used on Fedora. But those commands
  require exact names only. Allow switching between two variants only
  from prefix. That should work on all platforms. It should support also
  names like tsig-keygen-9.18 or tsig-keygen-9.21.

  The same case applies to named-checkzone and named-compilezone.
  :gl:`!12419`


