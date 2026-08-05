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

Notes for BIND 9.21.25
----------------------

New Features
~~~~~~~~~~~~

- Add a RPZ mode to named-checkzone.

  Provides a command line switch (named-checkzone -P) to treat the zone
  being loaded as an RPZ zone and check if the owner names are valid.
  :gl:`#262`

- Disclose active Negative Trust Anchors with Extended DNS Error 33.

  A Negative Trust Anchor (RFC 7646) turns off DNSSEC validation for a
  domain, so a name that would normally fail validation resolves
  instead. named now marks such answers with Extended DNS Error code 33,
  "Negative Trust Anchor", so operators can see at a glance when a
  response came back only because an NTA was in effect. :gl:`#6268`

- Built-in hints can be printed with named -H command.

  Additionally root hints were updated to precisely match authoritative
  source including comments. This is a cosmetic change IP addresses
  haven't been changed.

Feature Changes
~~~~~~~~~~~~~~~

- Batch qp transaction for RPZ updates.

  RPZ was built around fine-grained locking, but that forces the use of
  many small qp transactions. With this MR, we switch qp transaction to
  handle the full update to the rpz summary structure. While this
  serializes the RPZ updates, the reduced overhead from batching qp
  transactions more than compensates for it and results in improvements
  for big RPZ zones. :gl:`#5787`, #6270

Bug Fixes
~~~~~~~~~

- Dig +yaml producing invalid YAML when a lookup fails.

  When "dig +yaml" was run and no server could be reached, dig printed
  its plain-text startup banner (the "; \<\<\>\> DiG ..." and ";; global
  options" lines) ahead of the machine-readable output, so the result
  was not valid YAML and could not be parsed. dig no longer emits that
  banner in YAML mode. As part of the same change, the banner is now
  built only after the whole command line has been read, so options
  given after the query name (such as +nocmd, +short and +yaml) are
  correctly reflected in it. :gl:`#1230`

- Ensure NSEC authority does not cross zonecut boundary.

  When using a cached NSEC record to prove that a delegation is
  insecure, we now check that the signer name in the corresponding RRSIG
  is not above a known secure delegation point. This prevents a signed
  namespace from being downgraded to insecure using an NSEC record from
  the grandparent zone. :gl:`#5967`

- Treat non canonical RPZ prefixes as any other failure.

  RPZ prefixes that were not encoded in canonical form do not work.
  Treat them as any other encoding error. :gl:`#6043`

- Prevent aborts during expired cache dumps.

  Running rndc dumpdb -expired could cause named to abort when the cache
  contained internal deletion markers for records that had already been
  removed. BIND now skips those markers when preparing expired cache
  dumps, so the dump includes only real cached records and completes
  normally. :gl:`#6064`

- Properly prevent TSIG generation command line injection attacks.

  When key names are generated with `rndc-confgen`, `tsig-keygen` and
  `ddns-confgen`, special characters must be escaped to ensure the
  configuration is parsed correctly. :gl:`#6071`

- Prevent ddns-confgen self-domain update-policy injection.

  In `ddns-confgen`, the user-supplied domain name to be updated was not
  properly escaped and put inside a double-quoted string when generating
  the example code fragment.  This has been corrected. :gl:`#6072`

- Dnssec-signzone had a potential heap bounds overflow write.

  It was possible for `dnssec-signzone` to overflow array bounds while
  signing.  This has been fixed. :gl:`#6076`

- Restore SMF support on Solaris and illumos.

  SMF support on Solaris and illumos was silently dropped by a build
  system rewrite in 2018; it is now detected and enabled again.
  :gl:`#6096`

- Fix NULL pointer dereference in dnstap-read.

  It was possible to dereference a NULL pointer in dnstap-read causing
  it to exit on a malformed DNSTAP file.  This has been fixed.
  :gl:`#6124`

- Treat an unusable NSEC3 chain as a verification failure.

  When transferring in a mirror zone, DNSSEC verification could
  incorrectly succeed when the zone had an invalid `NSEC3PARAM` record,
  leading to subsequent validation failures. This has been fixed.
  :gl:`#6136`

- Unterminated OpenSSL private-key `Label:` field can be read past its
  parser buffer.

  Check that the string encoded in the Label: field of the .private file
  of a key pair is NUL terminated and the correct length.  Reject the
  .private file if it is not. :gl:`#6193`

- Dns_private_chains wasn't handling PRIVATE DNSSEC algorithms
  correctly.

  dns_private_chains wasn't looking for the private records that
  indicate that a zone is being signed by a PRIVATE DNSSEC algorithm.
  This has been fixed. :gl:`#6205`

- Negative caching stopped working with stale-answer-client-timeout 0.

  With "stale-answer-client-timeout 0" configured, every client query
  for a name cached as NXDOMAIN or NODATA was sent on to the
  authoritative servers, even while the cached negative answer was still
  within its TTL, so the resolver effectively lost negative caching.
  Negative answers are now refreshed only once they have actually gone
  stale. :gl:`#6245`

- Fix compilation on GNU/Hurd.

  Fix compilation issues on GNU/Hurd. :gl:`#6285`

- Resolver could return expired records instead of a negative answer.

  When an unvalidated negative answer (such as one obtained for a query
  with the "checking disabled" flag set) arrived for a name that had
  DNSSEC-validated records in the cache, those records blocked the
  negative answer from being cached even after they had passed their
  TTL, and the expired records could be returned to the client instead.
  Validated records that have expired no longer prevent negative answers
  from being cached.


