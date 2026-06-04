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

Notes for BIND 9.21.23
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix DNS64 owner case after DNAME restart.

  When BIND 9 is configured to use DNS64 and encounters a DNAME
  redirect, it could end up using freed memory for the DNS response
  owner name. This caused the response to contain corrupted data. This
  fix ensures the correct owner name is used when constructing the
  synthesized response after a DNAME redirect.

  ISC thanks Qifan Zhang of Palo Alto Networks for reporting the issue.
  :gl:`#5934`

Removed Features
~~~~~~~~~~~~~~~~

- Remove legacy special handling for SIG, NXT, and KEY records.

  BIND no longer applies legacy RFC 2535 handling to the obsolete
  ``SIG``, ``NXT`` and ``KEY`` record types; they are now served as
  plain zone data. Zones with both a ``CNAME`` and a ``KEY`` and or
  ``NXT`` at the same name — invalid under :rfc:`2181` — will now fail
  to load and must be corrected. :gl:`#6007`

Feature Changes
~~~~~~~~~~~~~~~

- Fall back to TCP on a UDP response with a mismatched query id.

  BIND used to wait silently for the correct DNS message id on a UDP
  fetch even after receiving a response from the expected server with
  the wrong id, leaving room for off-path spoofing attempts to keep
  guessing within that window.  The resolver now retries the fetch over
  TCP on the first such response, and a new MismatchTCP statistics
  counter tracks how often the fallback fires. :gl:`#5449`

- Cap glue records cached from a referral.

  named cached every glue record from a referral, retaining far more
  than resolution will ever use.  The number of nameservers and
  addresses kept per referral is now bounded in the delegation database.
  :gl:`#5701`

- Fix a resolver stall on a CNAME response to a DS query.

  A validating resolver could stall for about twelve seconds and then
  return SERVFAIL when an authoritative server answered a DS query with
  a CNAME. Such responses are now rejected promptly, so the query fails
  fast instead of hanging. :gl:`#5878`

- Named could crash on concurrent TKEY DELETE for the same key.

  On a server configured with tkey-gssapi-keytab (or
  tkey-gssapi-credential), an authenticated peer could crash named by
  sending two TKEY DELETE requests for the same dynamic key in rapid
  succession.  This has been fixed. :gl:`#6001`

Bug Fixes
~~~~~~~~~

- The resolver now removes other RRsets at the same name when caching a
  CNAME.

  When an RRset is in stale cache, and the authoritative server changes
  the record type to CNAME, the resolver fails to refresh the stale
  cache. This has been fixed. :gl:`#5302`

- Fix TCP fallback after repeated UDP timeouts.

  When an authoritative server failed to respond to two consecutive UDP
  queries in a fetch, named was supposed to retry the next attempt over
  TCP but in fact still sent it over UDP.  The resolver now properly
  switches the transport to TCP on the third attempt to the same server.
  :gl:`#5529`

- Enable Edwards curves with PKCS#11.

  Ed25519 and Ed448 curves did not work in PKCS#11. This has been fixed.
  :gl:`#5762`

- Fix nxdomain-redirect combined with dns64.

  When a resolver was configured with both `nxdomain-redirect` and
  `dns64` in the same view, an AAAA query for a nonexistent name could
  abort `named`. The combination failed whenever the redirect zone held
  A records but no AAAA records.  The server now serves the empty AAAA
  response from the redirect zone as-is, instead of attempting DNS64
  synthesis on top of it. :gl:`#5789`

- Clear REDIRECT flag when it isn't needed.

  When `nxdomain-redirect` is in use, and a recursive query is used to
  get the redirected answer, a flag is set to distinguish it from a
  normal recursive response. Previously, that flag was left set
  afterward, which could trigger an assertion if a normal recursive
  query was sent later on behalf of the same client: for example,
  because the `filter-aaaa` plugin was in use.  This has been fixed.
  :gl:`#5936`

- Disable output escaping in bind9.xsl.

  The statistics charts where not displaying on some browsers. This has
  been fixed. :gl:`#5990`

- Fix crash on badly configured secondary signer.

  A badly configured secondary signer that was missing the 'file' entry
  caused the server to crash, rather than to reject the configuration.
  This has been fixed. :gl:`#5993`

- Reject RRSIG records covering meta-types.

  A recursive resolver could accept and cache an RRSIG record whose
  Type-Covered field names a meta-type (ANY, AXFR, IXFR, MAILA, MAILB),
  even though no real RRset of those types ever exists. Such records are
  now rejected by the DNS message parser. :gl:`#6002`

- Restore delegdb size after `rndc flush`

  When the delegation database was flushed using `rndc flush`, its size
  was also reset but not restored. As a result, after `rndc flush` was
  used at least once, the delegation database size could grow unbounded.
  This has now been fixed.


