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

Notes for BIND 9.18.35
----------------------

Bug Fixes
~~~~~~~~~

- Fix deferred validation of unsigned DS and DNSKEY records.

  When processing a query with the "checking disabled" bit set (CD=1),
  :iscman:`named` stores the invalidated result in the cache, marked "pending".
  When the same query is sent with CD=0, the cached data is validated
  and either accepted as an answer, or ejected from the cache as
  invalid. This deferred validation was not attempted for DS and DNSKEY
  records if they had no cached signatures, causing spurious validation
  failures. The deferred validation is now completed in this scenario.

  Also, if deferred validation fails, the data is now re-queried to find
  out whether the zone has been corrected since the invalid data was
  cached. :gl:`#5066`

- Fix RPZ race condition during a reconfiguration.

  With RPZ in use, :iscman:`named` could terminate unexpectedly because of a
  race condition when a reconfiguration command was received using
  :iscman:`rndc`. This has been fixed. :gl:`#5146`

- "CNAME and other data check" not applied to all types.

  An incorrect optimization caused "CNAME and other data" errors not to
  be detected if certain types were at the same node as a CNAME.  This
  has been fixed. :gl:`#5150`

- Remove NSEC/DS/NSEC3 RRSIG check from ``dns_message_parse()``.

  Previously, when parsing responses, :iscman:`named` incorrectly rejected
  responses without matching RRSIG records for NSEC/DS/NSEC3 records in
  the authority section. This rejection, if appropriate, should have
  been left for the validator to determine and has been fixed.
  :gl:`#5185`


