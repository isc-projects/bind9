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

Notes for BIND 9.21.6
---------------------

New Features
~~~~~~~~~~~~

- Implement the min-transfer-rate-in configuration option.

  A new option 'min-transfer-rate-in <bytes> <minutes>' has been added
  to the view and zone configurations. It can abort incoming zone
  transfers which run very slowly due to network related issues, for
  example. The default value is set to 10240 bytes in 5 minutes.
  :gl:`#3914`

- Add HTTPS record query to host command line tool.

  The host command was extended to also query for the HTTPS RR type by
  default.

Feature Changes
~~~~~~~~~~~~~~~

- Drop malformed notify messages early instead of decompressing them.

  The DNS header shows if a message has multiple questions or invalid
  NOTIFY sections. We can drop these messages early, right after parsing
  the question. This matches RFC 9619 for multi-question messages and
  Unbound's handling of NOTIFY. We still parse the question to include
  it in our FORMERR response.

  Add drop_msg_early() function to check for these conditions: -
  Messages with more than one question, as required by RFC 9619 - NOTIFY
  query messages containing answer sections (like Unbound) - NOTIFY
  messages containing authority sections (like Unbound) :gl:`#5158`,
  #3656

- Reduce memory used to store DNS names.

  The memory used to internally store the DNS names has been reduced.

Bug Fixes
~~~~~~~~~

- Fix dual-stack-servers configuration option.

  The dual-stack-servers configuration option was not working as
  expected; the specified servers were not being used when they should
  have been, leading to resolution failures. This has been fixed.
  :gl:`#5019`

- Implement sig0key-checks-limit and sig0message-checks-limit.

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
  16. :gl:`#5050`

- Fix the data race causing a permanent active client increase.

  Previously, a data race could cause a newly created fetch context for
  a new client to be used before it had been fully initialized, which
  would cause the query to become stuck; queries for the same data would
  be either paused indefinitely or dropped because of the
  `clients-per-query` limit. This has been fixed. :gl:`#5053`

- Fix deferred validation of unsigned DS and DNSKEY records.

  When processing a query with the "checking disabled" bit set (CD=1),
  `named` stores the unvalidated result in the cache, marked "pending".
  When the same query is sent with CD=0, the cached data is validated,
  and either accepted as an answer, or ejected from the cache as
  invalid. This deferred validation was not attempted for DS and DNSKEY
  records if they had no cached signatures, causing spurious validation
  failures. We now complete the deferred validation in this scenario.

  Also, if deferred validation fails, we now re-query the data to find
  out whether the zone has been corrected since the invalid data was
  cached. :gl:`#5066`

- Fix RPZ race condition during a reconfiguration.

  With RPZ in use, `named` could terminate unexpectedly because of a
  race condition when a reconfiguration command was received using
  `rndc`. This has been fixed. :gl:`#5146`

- "CNAME and other data check" not applied to all types.

  An incorrect optimization caused "CNAME and other data" errors not to
  be detected if certain types were at the same node as a CNAME.  This
  has been fixed. :gl:`#5150`

- Use named Service Parameter Keys (SvcParamKeys) by default.

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
  :gl:`#5156`

- Relax private DNSKEY and RRSIG constraints.

  DNSKEY, KEY, RRSIG and SIG constraints have been relaxed to allow
  empty key and signature material after the algorithm identifier for
  PRIVATEOID and PRIVATEDNS. It is arguable whether this falls within
  the expected use of these types as no key material is shared and the
  signatures are ineffective but these are private algorithms and they
  can be totally insecure. :gl:`#5167`

- Remove NSEC/DS/NSEC3 RRSIG check from dns_message_parse.

  Previously, when parsing responses, named incorrectly rejected
  responses without matching RRSIG records for NSEC/DS/NSEC3 records in
  the authority section. This rejection, if appropriate, should have
  been left for the validator to determine and has been fixed.
  :gl:`#5185`

- Fix TTL issue with ANY queries processed through RPZ "passthru"

  Answers to an "ANY" query which were processed by the RPZ "passthru"
  policy had the response-policy's `max-policy-ttl` value unexpectedly
  applied. This has been fixed. :gl:`#5187`

- Dnssec-signzone needs to check for a NULL key when setting offline.

  dnssec-signzone could dereference a NULL key pointer when resigning a
  zone.  This has been fixed. :gl:`#5192`

- Fix a bug in the statistics channel when querying zone transfers
  information.

  When querying zone transfers information from the statistics channel
  there was a rare possibility that `named` could terminate unexpectedly
  if a zone transfer was in a state when transferring from all the
  available primary servers had failed earlier. This has been fixed.
  :gl:`#5198`

- Fix assertion failure when dumping recursing clients.

  Previously, if a new counter was added to the hashtable while dumping
  recursing clients via the `rndc recursing` command, and
  `fetches-per-zone` was enabled, an assertion failure could occur. This
  has been fixed. :gl:`#5200`

- Dump the active resolver fetches from dns_resolver_dumpfetches()

  Previously, active resolver fetches were only dumped when the
  `fetches-per-zone` configuration option was enabled. Now, active
  resolver fetches are dumped along with the number of
  `clients-per-server` counters per resolver fetch.


