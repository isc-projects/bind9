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

BIND 9.18.35
------------

New Features
~~~~~~~~~~~~

- Add digest methods for SIG and RRSIG. ``7f4023fe7d``

  ZONEMD digests RRSIG records and potentially digests SIG record. Add
  digests methods for both record types. :gl:`#5219` :gl:`!10219`

Bug Fixes
~~~~~~~~~

- Prevent a reference leak when using plugins. ``8d0d08ec00``

  The `NS_QUERY_DONE_BEGIN` and `NS_QUERY_DONE_SEND` plugin hooks could
  cause a reference leak if they returned `NS_HOOK_RETURN` without
  cleaning up the query context properly. :gl:`#2094` :gl:`!10171`

- Fix memory ordering issues with atomic operations in the quota.c
  module. ``86f02349e5``

  Change all the non-locked operations on `quota->used` and
  `quota->waiting` to "acq/rel" for inter-thread synchronization. Some
  loads are left as "relaxed", because they are under a locked mutex
  which also provides protection.

  Also use relaxed memory ordering for `quota->max` and `quota->soft`,
  as done in the main branch; possible ordering issues for these
  variables are acceptable. :gl:`#5018` :gl:`!10203`

- Fix deferred validation of unsigned DS and DNSKEY records.
  ``60a26ecd43``

  When processing a query with the "checking disabled" bit set (CD=1),
  `named` stores the unvalidated result in the cache, marked "pending".
  When the same query is sent with CD=0, the cached data is validated,
  and either accepted as an answer, or ejected from the cache as
  invalid. This deferred validation was not attempted for DS and DNSKEY
  records if they had no cached signatures, causing spurious validation
  failures. We now complete the deferred validation in this scenario.

  Also, if deferred validation fails, we now re-query the data to find
  out whether the zone has been corrected since the invalid data was
  cached. :gl:`#5066` :gl:`!10106`

- When recording an rr trace, use libtool. ``42afefe031``

  When a system test is run with the `USE_RR` environment variable set
  to 1, an `rr` trace is now correctly generated for each instance of
  `named`. :gl:`#5079` :gl:`!10208`

- Do not cache signatures for rejected data. ``7e24b9f6ec``

  The cache has been updated so that if new data is rejected - for
  example, because there was already existing data at a higher trust
  level - then its covering RRSIG will also be rejected. :gl:`#5132`
  :gl:`!10135`

- Fix a race issue in dns_view_addzone() ``a946528023``

  Views use two types of reference counting - regular and weak, and when
  there are no more regular references, the `view_flushanddetach()`
  function destroys or detaches some parts of the view, including
  `view->zonetable`, while other parts are freed by `destroy()` when the
  last weak reference is detached. Since catalog zones use weak
  references to attach a view, it's currently possible that during
  shutdown catalog zone processing will try to add a new zone into an
  otherwise unused view (because it's shutting down) which doesn't have
  an attached zonetable any more. This could cause an assertion failure.
  Fix this issue by modifying the `dns_view_addzone()` function to
  expect that `view->zonetable` can be `NULL`, and in that case just
  return `ISC_R_SHUTTINGDOWN`. :gl:`#5138` :gl:`!10086`

- Fix RPZ race condition during a reconfiguration. ``54bb8252e2``

  With RPZ in use, `named` could terminate unexpectedly because of a
  race condition when a reconfiguration command was received using
  `rndc`. This has been fixed. :gl:`#5146` :gl:`!10145`

- "CNAME and other data check" not applied to all types. ``aaaf2e989a``

  An incorrect optimization caused "CNAME and other data" errors not to
  be detected if certain types were at the same node as a CNAME.  This
  has been fixed. :gl:`#5150` :gl:`!10101`

- Remove NSEC/DS/NSEC3 RRSIG check from dns_message_parse.
  ``b601cb32ee``

  Previously, when parsing responses, named incorrectly rejected
  responses without matching RRSIG records for NSEC/DS/NSEC3 records in
  the authority section. This rejection, if appropriate, should have
  been left for the validator to determine and has been fixed.
  :gl:`#5185` :gl:`!10143`

- Fix a logic error in cache_name() ``ab047ff47f``

  A change in 6aba56ae8 (checking whether a rejected RRset was identical
  to the data it would have replaced, so that we could still cache a
  signature) inadvertently introduced cases where processing of a
  response would continue when previously it would have been skipped.
  :gl:`#5197` :gl:`!10159`

- Finalize removal of memory debug flags size and mctx [9.18]
  ``853a966fe7``

  :gl:`!9607`

- Post [CVE-2024-12705] Performance Drop Fixes, Part 2. ``e811f444b7``

  :gl:`!10193`

- Post [CVE-2024-12705] Performance Drop Fixes. ``8d96ff01d4``

  :gl:`!10128`

- Sync the TSAN CC, CFLAGS and LDFLAGS in the respdiff:tsan job.
  ``22fd7c4eb4``

  :gl:`!10213`


