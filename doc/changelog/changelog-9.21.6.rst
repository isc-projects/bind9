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

BIND 9.21.6
-----------

New Features
~~~~~~~~~~~~

- Implement the min-transfer-rate-in configuration option.
  ``a282f1ba3f``

  A new option 'min-transfer-rate-in <bytes> <minutes>' has been added
  to the view and zone configurations. It can abort incoming zone
  transfers which run very slowly due to network related issues, for
  example. The default value is set to 10240 bytes in 5 minutes.
  :gl:`#3914` :gl:`!9098`

- Add digest methods for SIG and RRSIG. ``fd48df20f3``

  ZONEMD digests RRSIG records and potentially digests SIG record. Add
  digests methods for both record types. :gl:`#5219` :gl:`!10217`

- Add HTTPS record query to host command line tool. ``d34414c47b``

  The host command was extended to also query for the HTTPS RR type by
  default. :gl:`!8642`

Removed Features
~~~~~~~~~~~~~~~~

- Clean up unnecessary code in qpcache. ``74c9ff384e``

  Removed some code from the cache database implementation that was left
  over from before it and the zone database implementation were
  separated. :gl:`!9991`

- Cleanup isc/util.h header and friends. ``239712df16``

  Cleanup short list macros from <isc/util.h>, remove two unused
  headers, move locking macros to respective headers and use only the
  C11 static assertion. :gl:`!10196`

- Remove check for the mandatory IPv6 support. ``daa9c17905``

  IPv6 Advanced Socket API (:rfc:`3542`) is a hard requirement, remove
  the autoconf check to speed up the ./configure run a little bit.
  :gl:`!10201`

- Remove log initialization checks from named. ``1b3e7f52ec``

  Logging initialization check is now redundant as there is a default
  global log context created during libisc's constructor.

  `isc_log` calls can safely be made at any time outside libisc's
  constructor. :gl:`!10186`

Feature Changes
~~~~~~~~~~~~~~~

- Refactor and simplify isc_symtab. ``5559539eb0``

  This commit does several changes to isc_symtab:

  1. Rewrite the isc_symtab to internally use isc_hashmap instead of
  hand-stiched hashtable.

  2. Create a new isc_symtab_define_and_return() api, which returns
  the already defined symvalue on ISC_R_EXISTS; this allows users    of
  the API to skip the isc_symtab_lookup()+isc_symtab_define()    calls
  and directly call isc_symtab_define_and_return().

  3. Merge isccc_symtab into isc_symtab - the only missing function
  was isccc_symtab_foreach() that was merged into isc_symtab API.

  4. Add full set of unit tests for the isc_symtab API. :gl:`#5103`
  :gl:`!9921`

- Drop malformed notify messages early instead of decompressing them.
  ``7fce7707db``

  The DNS header shows if a message has multiple questions or invalid
  NOTIFY sections. We can drop these messages early, right after parsing
  the question. This matches RFC 9619 for multi-question messages and
  Unbound's handling of NOTIFY. We still parse the question to include
  it in our FORMERR response.

  Add drop_msg_early() function to check for these conditions: -
  Messages with more than one question, as required by RFC 9619 - NOTIFY
  query messages containing answer sections (like Unbound) - NOTIFY
  messages containing authority sections (like Unbound) :gl:`#5158`,
  #3656 :gl:`!10056`

- Cleanup parts of the isc_mem API. ``4ba1ccfa2e``

  This MR changes custom attach/detach implementation with refcount
  macros, replaces isc_mem_destroy() with isc_mem_detach(), and does
  various small cleanups. :gl:`!9456`

- Move the library initialization and shutdown to executables.
  ``6e0c1f151c``

  Instead of relying on unreliable order of execution of the library
  constructors and destructors, move them to individual binaries.  The
  advantage is that the execution time and order will remain constant
  and will not depend on the dynamic load dependency solver.
  :gl:`!10069`

- Reduce memory used to store DNS names. ``24db1b1a8a``

  The memory used to internally store the DNS names has been reduced.
  :gl:`!10140`

- Unify fips handling to isc_crypto and make the toggle one way.
  ``3de629d6b7``

  Since algorithm fetching is handled purely in libisc, FIPS mode
  toggling can be purely done in within the library instead of provider
  fetching in the binary for OpenSSL >=3.0.

  Disabling FIPS mode isn't a realistic requirement and isn't done
  anywhere in the codebase. Make the FIPS mode toggle enable-only to
  reflect the situation. :gl:`!9920`

Bug Fixes
~~~~~~~~~

- Prevent a reference leak when using plugins. ``5604d3a44e``

  The `NS_QUERY_DONE_BEGIN` and `NS_QUERY_DONE_SEND` plugin hooks could
  cause a reference leak if they returned `NS_HOOK_RETURN` without
  cleaning up the query context properly. :gl:`#2094` :gl:`!9971`

- Fix isc_quota bug. ``742d379d88``

  Running jobs which were entered into the isc_quota queue is the
  responsibility of the isc_quota_release() function, which, when
  releasing a previously acquired quota, checks whether the queue is
  empty, and if it's not, it runs a job from the queue without touching
  the 'quota->used' counter. This mechanism is susceptible to a possible
  hangup of a newly queued job in case when between the time a decision
  has been made to queue it (because used >= max) and the time it was
  actually queued, the last quota was released. Since there is no more
  quotas to be released (unless arriving in the future), the newly
  entered job will be stuck in the queue.

  Fix the issue by adding checks in both isc_quota_release() and
  isc_quota_acquire_cb() to make sure that the described hangup does not
  happen. Also see code comments. :gl:`#4965` :gl:`!10082`

- Fix dual-stack-servers configuration option. ``6af708f3b0``

  The dual-stack-servers configuration option was not working as
  expected; the specified servers were not being used when they should
  have been, leading to resolution failures. This has been fixed.
  :gl:`#5019` :gl:`!9708`

- Implement sig0key-checks-limit and sig0message-checks-limit.
  ``d78ebff861``

  Previously a hard-coded limitation of maximum two key or message
  verification checks were introduced when checking the message's SIG(0)
  signature. It was done in order to protect against possible DoS
  attacks. The logic behind choosing the number 2 was that more than a
  single key should only be required during key rotations, and in that
  case two keys are enough. But later it became apparent that there are
  other use cases too where even more keys are required, see issue
  number #5050 in GitLab.

  This change introduces two new configuration options for the views,
  `sig0key-checks-limit` and `sig0message-checks-limit`, which define
  how many keys are allowed to be checked to find a matching key, and
  how many message verifications are allowed to take place once a
  matching key has been found. The latter protects against expensive
  cryptographic operations when there are keys with colliding tags and
  algorithm numbers, with default being 2, and the former protects
  against a bit less expensive key parsing operations and defaults to
  16. :gl:`#5050` :gl:`!9967`

- Fix the data race causing a permanent active client increase.
  ``479c366c2b``

  Previously, a data race could cause a newly created fetch context for
  a new client to be used before it had been fully initialized, which
  would cause the query to become stuck; queries for the same data would
  be either paused indefinitely or dropped because of the
  `clients-per-query` limit. This has been fixed. :gl:`#5053`
  :gl:`!10146`

- Fix deferred validation of unsigned DS and DNSKEY records.
  ``ebf1606f38``

  When processing a query with the "checking disabled" bit set (CD=1),
  `named` stores the unvalidated result in the cache, marked "pending".
  When the same query is sent with CD=0, the cached data is validated,
  and either accepted as an answer, or ejected from the cache as
  invalid. This deferred validation was not attempted for DS and DNSKEY
  records if they had no cached signatures, causing spurious validation
  failures. We now complete the deferred validation in this scenario.

  Also, if deferred validation fails, we now re-query the data to find
  out whether the zone has been corrected since the invalid data was
  cached. :gl:`#5066` :gl:`!10104`

- When recording an rr trace, use libtool. ``6320586df0``

  When a system test is run with the `USE_RR` environment variable set
  to 1, an `rr` trace is now correctly generated for each instance of
  `named`. :gl:`#5079` :gl:`!10197`

- Do not cache signatures for rejected data. ``fc3a4d6f89``

  The cache has been updated so that if new data is rejected - for
  example, because there was already existing data at a higher trust
  level - then its covering RRSIG will also be rejected. :gl:`#5132`
  :gl:`!9999`

- Fix wrong logging severity in do_nsfetch() ``1f6a16e6d0``

  ISC_LOG_WARNING was used while ISC_LOG_DEBUG(3) was implied.
  :gl:`#5145` :gl:`!10017`

- Fix RPZ race condition during a reconfiguration. ``5ba811bea2``

  With RPZ in use, `named` could terminate unexpectedly because of a
  race condition when a reconfiguration command was received using
  `rndc`. This has been fixed. :gl:`#5146` :gl:`!10079`

- "CNAME and other data check" not applied to all types. ``b694acbe45``

  An incorrect optimization caused "CNAME and other data" errors not to
  be detected if certain types were at the same node as a CNAME.  This
  has been fixed. :gl:`#5150` :gl:`!10033`

- Use named Service Parameter Keys (SvcParamKeys) by default.
  ``3f61a87be3``

  When converting SVCB records to text representation `named` now uses
  named `SvcParamKeys` values unless backward-compatible mode is
  activated, in which case the values which were not defined initially
  in RFC9460 and were added later (see [1]) are converted to opaque
  "keyNNNN" syntax, like, for example, "key7" instead of "dohpath".

  Also a new `+[no]svcparamkeycompat` option is implemented for `dig`,
  which enables the backward-compatible mode and uses the opaque syntax,
  if required for interoperability with other software or scripts. By
  default, the compatibility mode is disabled.

  [1] https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
  :gl:`#5156` :gl:`!10085`

- Relax private DNSKEY and RRSIG constraints. ``1bc7016d7a``

  DNSKEY, KEY, RRSIG and SIG constraints have been relaxed to allow
  empty key and signature material after the algorithm identifier for
  PRIVATEOID and PRIVATEDNS. It is arguable whether this falls within
  the expected use of these types as no key material is shared and the
  signatures are ineffective but these are private algorithms and they
  can be totally insecure. :gl:`#5167` :gl:`!10083`

- Delete dead nodes when committing a new version. ``67255da4b3``

  In the qpzone implementation of `dns_db_closeversion()`, if there are
  changed nodes that have no remaining data, delete them. :gl:`#5169`
  :gl:`!10089`

- Revert "Delete dead nodes when committing a new version"
  ``b652d5327c``

  This reverts commit 67255da4b376f65138b299dcd5eb6a3b7f9735a9,
  reversing changes made to 74c9ff384e695d1b27fa365d1fee84576f869d4c.
  :gl:`#5169` :gl:`!10224`

- Fix dns_qp_insert() checks in qpzone. ``d6b63210a8``

  Remove code in the QP zone database to handle failures of
  `dns_qp_insert()` which can't actually happen. :gl:`#5171`
  :gl:`!10088`

- Remove NSEC/DS/NSEC3 RRSIG check from dns_message_parse.
  ``f0785fedf1``

  Previously, when parsing responses, named incorrectly rejected
  responses without matching RRSIG records for NSEC/DS/NSEC3 records in
  the authority section. This rejection, if appropriate, should have
  been left for the validator to determine and has been fixed.
  :gl:`#5185` :gl:`!10125`

- Fix TTL issue with ANY queries processed through RPZ "passthru"
  ``23c1fbc609``

  Answers to an "ANY" query which were processed by the RPZ "passthru"
  policy had the response-policy's `max-policy-ttl` value unexpectedly
  applied. This has been fixed. :gl:`#5187` :gl:`!10176`

- Save time when creating a slab from another slab. ``cf981ab13b``

  The `dns_rdataslab_fromrdataset()` function creates a slab from an
  rdataset. If the source rdataset already uses a slab, then no
  processing is necessary; we can just copy the existing slab to a new
  location. :gl:`#5188` :gl:`!10162`

- Dnssec-signzone needs to check for a NULL key when setting offline.
  ``26f8ee7229``

  dnssec-signzone could dereference a NULL key pointer when resigning a
  zone.  This has been fixed. :gl:`#5192` :gl:`!10161`

- Acquire the database reference before possibly last node release.
  ``c4868b5bd9``

  Acquire the database reference in the detachnode() to prevent the last
  reference to be release while the NODE_LOCK being locked.  The
  NODE_LOCK is locked/unlocked inside the RCU critical section, thus it
  is most probably this should not pose a problem as the database uses
  call_rcu memory reclamation, but this it is still safer to acquire the
  reference before releasing the node. :gl:`#5194` :gl:`!10155`

- Fix a logic error in cache_name() ``02ef8ff01c``

  A change in 6aba56ae8 (checking whether a rejected RRset was identical
  to the data it would have replaced, so that we could still cache a
  signature) inadvertently introduced cases where processing of a
  response would continue when previously it would have been skipped.
  :gl:`#5197` :gl:`!10157`

- Fix a bug in the statistics channel when querying zone transfers
  information. ``e02d73e7e3``

  When querying zone transfers information from the statistics channel
  there was a rare possibility that `named` could terminate unexpectedly
  if a zone transfer was in a state when transferring from all the
  available primary servers had failed earlier. This has been fixed.
  :gl:`#5198` :gl:`!10182`

- Fix assertion failure when dumping recursing clients. ``796b662b92``

  Previously, if a new counter was added to the hashtable while dumping
  recursing clients via the `rndc recursing` command, and
  `fetches-per-zone` was enabled, an assertion failure could occur. This
  has been fixed. :gl:`#5200` :gl:`!10164`

- Validating ADB fetches could cause a crash in import_rdataset()
  ``49ccbe857a``

  Previously, in some cases, the resolver could return rdatasets of type
  CNAME or DNAME without the result code being set to `DNS_R_CNAME` or
  `DNS_R_DNAME`. This could trigger an assertion failure in the ADB. The
  resolver error has been fixed. :gl:`#5201` :gl:`!10172`

- Call isc__iterated_hash_initialize in isc__work_cb. ``f3458fdf43``

  isc_iterated_hash didn't work in offloaded threads as the per thread
  initialisation has not been done.  This has been fixed. :gl:`#5214`
  :gl:`!10206`

- Fix a bug in get_request_transport_type() ``db5166ab99``

  When `dns_remote_done()` is true, calling `dns_remote_curraddr()`
  asserts. Add a `dns_remote_curraddr()` check before calling
  `dns_remote_curraddr()`. :gl:`#5215` :gl:`!10222`

- Clean up dns_rdataslab module. ``948f8d7a98``

  Rdata slabs used in the QP databases are usually prepended with a slab
  header, but are sometimes "raw", containing only the rdata and no
  header. Previously, to allow for them to be used both ways, functions
  that operated on them took a `reservelen` argument, which would be set
  to either the header length or to zero, and skipped over that many
  bytes at the beginning of the buffer. Most such functions were never
  used on the raw form. To make the code clearer, each of these
  functions now operates on full slabs with headers, and an alternate
  "raw" version of the function has been added in cases where that was
  needed.

  In addition, the `dns_rdataslab_merge()` and `_subtract()` functions
  have been rewritten for clarity and efficiency, and a minor bug has
  been fixed in `dns_rdataslab_equal()` and `_equalx()`, which could
  cause an incorrect result if both slabs being compared had zero
  length. :gl:`!10084`

- Dump the active resolver fetches from dns_resolver_dumpfetches()
  ``5d0c347e75``

  Previously, active resolver fetches were only dumped when the
  `fetches-per-zone` configuration option was enabled. Now, active
  resolver fetches are dumped along with the number of
  `clients-per-server` counters per resolver fetch. :gl:`!10107`

- Fix the foundname vs dcname madness in qpcache_findzonecut()
  ``4e68dbf194``

  The qpcache_findzonecut() accepts two "foundnames": 'foundname' and
  'dcname' could be NULL.  Originally, when 'dcname' would be NULL, the
  'dcname' would be set to 'foundname' which basically means that we
  were copying the .ndata over itself for no apparent reason.
  :gl:`!10049`

- Post [CVE-2024-12705] Performance Drop Fixes, Part 2. ``c8104daf8d``

  This merge request addresses several key performance bottlenecks in
  the DoH (DNS over HTTPS) implementation by introducing significant
  optimizations and improvements.

  ### Key Improvements

  1. **Simplification and Optimisation of `http_do_bio()` Function**:
  - The code flow in the `http_do_bio()` function has been significantly
  simplified. 2. **Flushing HTTP Write Buffer on Outgoing DNS
  Messages**:    - The buffer is flushed and a send operation is
  performed when there is an outgoing DNS message. 3. **Bumping Active
  Streams Processing Limit**:    - The total number of active streams
  has been increased to 60% of the total streams limit.

  These changes collectively enhance the performance and reliability of
  the DoH implementation, making it more efficient and robust for
  handling high-load scenarios, particularly noticeable in long runs (>=
  1h) of `stress:long:rpz:doh+udp:linux:*` tests. It improves perf. for
  tests for BIND 9.18, but it likely will have a positive but less
  pronounced effect on newer versions as well.

  In essence, the merge request fixes three bottlenecks stacked upon
  each other.

  *It is a logical continuation of the merge requests !10109.* !10109,
  unfortunately, did not completely [address the performance drop in
  9.18](https://gitlab.isc.org/isc-projects/bind9/-/pipelines/221545)
  for longer runs of the stress test. This merge request [addresses
  that](https://gitlab.isc.org/isc-projects/bind9/-/pipelines/223661).

  **P.S.**

  The origin of the fixes is, in fact, the branch in !10193. So this MR
  is a ... *forward port* of them. :gl:`!10192`

- Post [CVE-2024-12705] Performance Drop Fixes. ``3033d127d2``

  This merge request fixes a [performance
  drop](https://gitlab.isc.org/isc-projects/bind9/-/pipelines/216728)
  after merging the fixes for #4795, in particular in 9.18.

  The MR [fixes the
  problem](https://gitlab.isc.org/isc-projects/bind9/-/pipelines/219825)
  without affecting performance for the newer versions, in particular
  for [the development version](https://gitlab.isc.org/isc-projects/bind
  9/-/pipelines/220619). :gl:`!10109`

- Remove 'target' from dns_adb. ``764eb65cf6``

  When a server name turns out to be a CNAME or DNAME, the ADB does not
  use it, but the `dns_adbname` structure still stored a copy of the
  target name. This is unnecessary and the code has been removed.
  :gl:`!10149`

- Simplify some dns_name API calls. ``e16560a650``

  Several functions in the `dns_name` module have had parameters
  removed, that were rarely or never used: - `dns_name_fromtext()` and
  `dns_name_concatenate()` no longer take a target buffer. -
  `dns_name_towire()` no longer takes a compression offset pointer; this
  is now part of the compression context. - `dns_name_towire()` with a
  `NULL` compression context will copy name data directly into a buffer
  with no processing. :gl:`!10152`

- Sync the TSAN CC, CFLAGS and LDFLAGS in the respdiff:tsan job.
  ``22b5442722``

  :gl:`!10209`


