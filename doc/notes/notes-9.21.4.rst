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

Notes for BIND 9.21.4
---------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2024-12705] DNS-over-HTTP(s) flooding fixes.

  Fix DNS-over-HTTP(S) implementation issues that arise under heavy
  query load. Optimize resource usage for :iscman:`named` instances that
  accept queries over DNS-over-HTTP(S).

  Previously, :iscman:`named` would process all incoming HTTP/2 data at
  once, which could overwhelm the server, especially when dealing with
  clients that send requests but don't wait for responses. That has been
  fixed. Now, :iscman:`named` handles HTTP/2 data in smaller chunks and
  throttles reading until the remote side reads the response data. It
  also throttles clients that send too many requests at once.

  Additionally, :iscman:`named` now carefully processes data sent by
  some clients, which can be considered "flooding." It logs these
  clients and drops connections from them. :gl:`#4795`

  In some cases, :iscman:`named` could leave DNS-over-HTTP(S)
  connections in the `CLOSE_WAIT` state indefinitely. That also has been
  fixed. ISC would like to thank JF Billaud for thoroughly investigating
  the issue and verifying the fix. :gl:`#5083` :gl:`#4795` :gl:`#5083`

- [CVE-2024-11187] Limit the additional processing for large RDATA sets.

  When answering queries, don't add data to the additional section if
  the answer has more than 13 names in the RDATA. This limits the number
  of lookups into the database(s) during a single client query, reducing
  query processing load. :gl:`#5034`

New Features
~~~~~~~~~~~~

- Add Extended DNS Error Code 22 - No Reachable Authority.

  When the resolver is trying to query an authority server and
  eventually timed out, a SERVFAIL answer is given to the client. Add
  the Extended DNS Error Code 22 - No Reachable Authority to the
  response. :gl:`#2268`

- Add "Zone has [AAAA/A] records but is not served by IPv[6/4]"
  warnings.

  Check that zones with AAAA records are served by IPv6 servers and that
  zones with A records are served by IPv4 servers. Sometimes, IPv6
  services are accidentally misconfigured and zones with IPv6 (AAAA)
  address records are not served by DNS servers with IPv6 addresses,
  which means they need to use translation devices to look up those IPv6
  addresses. The reverse is also sometimes true: zones with A records
  are not resolvable over IPv4 when they should be. To prevent this,
  BIND now looks for these misconfigured zones and issues a warning if
  they are found. :gl:`#4370`

- Add a new option to configure the maximum number of outgoing queries
  per client request.

  The configuration option 'max-query-count' sets how many outgoing
  queries per client request is allowed. The existing
  'max-recursion-queries' is the number of permissible queries for a
  single name and is reset on every CNAME redirection. This new option
  is a global limit on the client request. The default is 200.

  This allows us to send a bit more queries while looking up a single
  name. The default for 'max-recursion-queries' is changed from 32 to
  50. :gl:`#4980`  :gl:`#4921`

Removed Features
~~~~~~~~~~~~~~~~

- Remove dnssec-must-be-secure feature.

  :gl:`#4482`

- Remove 'sortlist' option.

  The `sortlist` option, which was deprecated in BIND 9.20, has now been
  removed. :gl:`#4665`

- Remove fixed value for the rrset-order option.

  Remove the "fixed" value from the "rrset-order" option and from the
  autoconf script. :gl:`#4666`

- Remove trusted-keys and managed-keys options.

  These options have been deprecated in 9.19 in favor of the
  'trust-anchors' option and are now being removed. :gl:`#5080`

Feature Changes
~~~~~~~~~~~~~~~

- The configuration clauses parental-agents and primaries are renamed to
  remote-servers.

  The top blocks 'primaries' and 'parental-agents' are no longer
  preferred and should be renamed to 'remote-servers'. The zone
  statements 'parental-agents' and 'primaries' are still used, and may
  refer to any 'remote-servers' top block. :gl:`#4544`

Bug Fixes
~~~~~~~~~

- Fix nsupdate hang when processing a large update.

  To mitigate DNS flood attacks over a single TCP connection, we
  throttle the connection when the other side does not read the data.
  Throttling should only occur on server-side sockets, but erroneously
  also happened for nsupdate, which acts as a client. When nsupdate
  started throttling the connection, it never attempts to read again.
  This has been fixed.   :gl:`#4910`

- Fix possible assertion failure when reloading server while processing
  updates.

  :gl:`#5006`

- Preserve cache across reconfig when using attach-cache.

  When the `attach-cache` option is used in the `options` block with an
  arbitrary name, it causes all views to use the same cache. Previously,
  this configuration caused the cache to be deleted and a new cache
  created every time the server was reconfigured. This has been fixed.
  :gl:`#5061`

- Resolve the spurious drops in performance due GLUE cache.

  For performance reasons, the returned GLUE records are cached on the
  first use.  The current implementation could randomly cause a
  performance drop and increased memory use.  This has been fixed.
  :gl:`#5064`

- Fix dnssec-signzone signing non-DNSKEY RRsets with revoked keys.

  `dnssec-signzone` was using revoked keys for signing RRsets other than
  DNSKEY.  This has been corrected. :gl:`#5070`

- Disable deterministic ecdsa for fips builds.

  FIPS 186-5 [1] allows the usage deterministic ECDSA (Section 6.3)
  which is compabile with RFC 6979 [2] but OpenSSL seems to follow FIPS
  186-4 (Section 6.3) [3] which only allows for random k values, failing
  k value generation for OpenSSL >=3.2. [4]

  Fix signing by not using deterministic ECDSA when FIPS mode is active.

  [1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf [2]:
  https://datatracker.ietf.org/doc/html/rfc6979 [3]:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf [4]: https:
  //github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b
  1e64/crypto/ec/ecdsa_ossl.c#L201-L207 :gl:`#5072`

- Unknown directive in resolv.conf not handled properly.

  The line after an unknown directive in resolv.conf could accidentally
  be skipped, potentially affecting dig, host, nslookup, nsupdate, or
  delv. This has been fixed. :gl:`#5084`

- Querying an NSEC3-signed zone for an empty record could trigger an
  assertion.

  A bug in the qpzone database could trigger a crash when querying for a
  deleted name, or a newly-added empty non-terminal name, in an
  NSEC3-signed zone. This has been fixed. :gl:`#5108`

- Fix response policy zones and catalog zones with an $INCLUDE statement
  defined.

  Response policy zones (RPZ) and catalog zones were not working
  correctly if they had an $INCLUDE statement defined. This has been
  fixed. :gl:`#5111`


