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

- Add an RPZ mode to :iscman:`named-checkzone`.

  Provides a command line switch, :option:`named-checkzone -P`, to treat
  the zone being loaded as an RPZ zone and check that the owner names
  are valid. :gl:`#262`

- Disclose active Negative Trust Anchors with Extended DNS Error 33.

  A Negative Trust Anchor (:rfc:`7646`) turns off DNSSEC validation for
  a domain, so a name that would normally fail validation resolves
  instead. :iscman:`named` now marks such answers with Extended DNS
  Error code 33, "Negative Trust Anchor", so operators can see at a
  glance when a response came back only because an NTA was in effect.
  :gl:`#6268`

- Built-in hints can be printed with the :option:`named -H` command.

  The built-in root hints were also updated to precisely match the
  authoritative source, including comments; this is a cosmetic change
  and the IP addresses have not changed. :gl:`!11114`

Feature Changes
~~~~~~~~~~~~~~~

- Speed up RPZ policy zone updates.

  RPZ updates used to be applied one small step at a time, adding
  overhead on large policy zones. Updates are now applied as a single
  batch, improving update performance for large RPZ zones, at the cost
  of no longer overlapping with concurrent updates. :gl:`#5787`
  :gl:`#6270`

Bug Fixes
~~~~~~~~~

- :option:`dig +yaml` was producing invalid YAML when a lookup failed.

  When no server could be reached, :iscman:`dig` printed its
  plain-text startup banner ahead of the YAML output, making the
  result unparsable. :iscman:`dig` no longer does this, and correctly
  reflects options such as ``+nocmd``, ``+short``, and ``+yaml``
  regardless of where they appear on the command line. :gl:`#1230`

- :option:`host -a` now uses TCP, as documented. :gl:`#2072`

- Ensure NSEC authority does not cross zonecut boundary.

  When using a cached NSEC record to prove that a delegation is
  insecure, :iscman:`named` now checks that the signer name in the
  corresponding RRSIG is not above a known secure delegation point.
  This prevents a signed namespace from being downgraded to insecure
  using an NSEC record from the grandparent zone. :gl:`#5967`

- Treat non-canonical RPZ prefixes as any other failure.

  RPZ prefixes that were not encoded in canonical form did not work.
  Treat them as any other encoding error. :gl:`#6043`

- Prevent aborts during expired cache dumps.

  Running :option:`rndc dumpdb -expired <rndc dumpdb>` could cause
  :iscman:`named` to abort if the cache held already-deleted entries.
  These are now skipped, so the dump completes normally. :gl:`#6064`

- Properly prevent TSIG generation command line injection attacks.

  When key names are generated with :iscman:`rndc-confgen`,
  :iscman:`tsig-keygen`, and :iscman:`ddns-confgen`, special characters
  must be escaped to ensure the configuration is parsed correctly.
  :gl:`#6071`

- Prevent :iscman:`ddns-confgen` self-domain update-policy injection.

  A user-supplied domain name was not properly escaped, allowing
  injection into the generated update-policy configuration. This has
  been fixed. :gl:`#6072`

- Fix a potential heap bounds overflow write in :iscman:`dnssec-signzone`.

  It was possible for :iscman:`dnssec-signzone` to overflow array
  bounds while signing. This has been fixed. :gl:`#6076`

- Restore SMF support on Solaris and illumos. :gl:`#6096`

- Fix crashes on invalid DNSTAP input in :iscman:`dnstap-read`.

  Malformed DNSTAP files could trigger a NULL pointer dereference or an
  out-of-bounds memory read in :iscman:`dnstap-read`. This has been
  fixed. :gl:`#6077` :gl:`#6124`

- Treat an unusable NSEC3 chain as a verification failure.

  When transferring in a mirror zone, DNSSEC verification could
  incorrectly succeed when the zone had an invalid NSEC3PARAM record,
  leading to subsequent validation failures. This has been fixed.
  :gl:`#6136`

- Unterminated OpenSSL private-key ``Label:`` field could be read past
  its parser buffer.

  The ``Label:`` field in a ``.private`` key file is now checked for
  length and NUL-termination. Malformed files are rejected. :gl:`#6193`

- Negative caching stopped working with stale-answer-client-timeout set
  to ``0``.

  Negative answers were re-fetched on every query instead of once they
  actually expired, effectively disabling negative caching. This has
  been fixed. :gl:`#6245`

- Fix compilation on GNU/Hurd. :gl:`#6285`

- Resolver could return expired records instead of a negative answer.

  When an unvalidated negative answer (such as one obtained for a query
  with the checking-disabled (CD) bit set) arrived for a name that had
  DNSSEC-validated records in the cache, those records blocked the
  negative answer from being cached even after they had passed their
  TTL, and the expired records could be returned to the client instead.
  Validated records that have expired no longer prevent negative
  answers from being cached. :gl:`!12423`


