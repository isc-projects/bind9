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

BIND 9.21.4
-----------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2024-12705] DNS-over-HTTP(s) flooding fixes. ``bddaff32104``

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
  ``4d054cca7a0``

  When answering queries, don't add data to the additional section if
  the answer has more than 13 names in the RDATA. This limits the number
  of lookups into the database(s) during a single client query, reducing
  query processing load. :gl:`#5034`

New Features
~~~~~~~~~~~~

- Add Extended DNS Error Code 22 - No Reachable Authority.
  ``3972eacdad2``

  When the resolver is trying to query an authority server and
  eventually timed out, a SERVFAIL answer is given to the client. Add
  the Extended DNS Error Code 22 - No Reachable Authority to the
  response. :gl:`#2268` :gl:`!9743`

- Enable extraction of exact local socket addresses. ``44d5dbeab63``

  Enable extracting the exact address/port that a local wildcard/TCP
  socket is bound to, improving the accuracy of dnstap logging and
  providing more information in debug logs produced by system tests.
  Since this requires issuing an extra system call on some hot paths,
  this new feature is only enabled when the ``ISC_SOCKET_DETAILS``
  preprocessor macro is set at compile time. :gl:`#4344` :gl:`!8348`

- Log both "from" and "to" socket in debug messages. ``6230bc883a5``

  Debug messages logging network traffic now include information about
  both sides of each communication channel rather than just one of them.
  :gl:`#4345` :gl:`!8349`

- Add "Zone has [AAAA/A] records but is not served by IPv[6/4]"
  warnings. ``ef6dc36e530``

  Check that zones with AAAA records are served by IPv6 servers and that
  zones with A records are served by IPv4 servers. Sometimes, IPv6
  services are accidentally misconfigured and zones with IPv6 (AAAA)
  address records are not served by DNS servers with IPv6 addresses,
  which means they need to use translation devices to look up those IPv6
  addresses. The reverse is also sometimes true: zones with A records
  are not resolvable over IPv4 when they should be. To prevent this,
  BIND now looks for these misconfigured zones and issues a warning if
  they are found. :gl:`#4370` :gl:`!8393`

- Add a new option to configure the maximum number of outgoing queries
  per client request. ``80a5745a1f8``

  The configuration option 'max-query-count' sets how many outgoing
  queries per client request is allowed. The existing
  'max-recursion-queries' is the number of permissible queries for a
  single name and is reset on every CNAME redirection. This new option
  is a global limit on the client request. The default is 200.

  This allows us to send a bit more queries while looking up a single
  name. The default for 'max-recursion-queries' is changed from 32 to
  50. :gl:`#4980`  :gl:`#4921` :gl:`!9737`

Removed Features
~~~~~~~~~~~~~~~~

- Remove dnssec-must-be-secure feature. ``f5f792f1ed2``

  :gl:`#4482` :gl:`!9851`

- Remove 'sortlist' option. ``2bce06e170a``

  The `sortlist` option, which was deprecated in BIND 9.20, has now been
  removed. :gl:`#4665` :gl:`!9839`

- Remove fixed value for the rrset-order option. ``5bee088dd1f``

  Remove the "fixed" value from the "rrset-order" option and from the
  autoconf script. :gl:`#4666` :gl:`!9852`

- Remove the log message about incomplete IPv6 API. ``3779a81d501``

  The log message would not be ever reached, because the IPv6 API is
  always considered to be complete.  Just remove the dead code.
  :gl:`#5068` :gl:`!9798`

- Remove trusted-keys and managed-keys options. ``9de6b228d41``

  These options have been deprecated in 9.19 in favor of the
  'trust-anchors' option and are now being removed. :gl:`#5080`
  :gl:`!9855`

- Drop single-use RETERR macro. ``f6ff4fff85e``

  If the RETERR define is only used once in a file, just drop the macro.
  :gl:`!9871`

- Remove C++ support from the public header. ``8d9bc93e81e``

  Since BIND 9 headers are not longer public, there's no reason to keep
  the ISC_LANG_BEGINDECL and ISC_LANG_ENDDECL macros to support
  including them from C++ projects. :gl:`!9925`

- Remove DLV remnants. ``f4377a3cd69``

  DLV is long gone, so we can remove design documentation around DLV,
  related command line options (that were already a hard failure), and
  some DLV related test remnants. :gl:`!9888`

Feature Changes
~~~~~~~~~~~~~~~

- Update picohttpparser.{c,h} with upstream repository. ``9428077f481``

  :gl:`#4485` :gl:`!9857`

- The configuration clauses parental-agents and primaries are renamed to
  remote-servers. ``858ba71eafc``

  The top blocks 'primaries' and 'parental-agents' are no longer
  preferred and should be renamed to 'remote-servers'. The zone
  statements 'parental-agents' and 'primaries' are still used, and may
  refer to any 'remote-servers' top block. :gl:`#4544` :gl:`!9822`

- Add TLS SNI extension to all outgoing TLS connections. ``6eb77ed2b07``

  This change ensures that SNI extension is used in outgoing connections
  over TLS (e.g. for DoT and DoH) when applicable. :gl:`#5099`
  :gl:`!9923`

- Detect and possibly define constexpr using Autoconf. ``1fea227ab8b``

  Previously, we had an ISC_CONSTEXPR macro that was expanded to either
  `constexpr` or `static const`, depending on compiler support.  To make
  the code cleaner, move `constexpr` support detection to Autoconf; if
  `constexpr` support is missing from the compiler, define `constexpr`
  as `static const` in config.h. :gl:`!9924`

- Remove unused maxquerycount. ``43622594f48``

  Related to #4980 :gl:`!9850`

- Use query counters in validator code. ``63060314098``

  Commit af7db8951364a89c468eda1535efb3f53adc2c1f as part of #4141 was
  supposed to apply the 'max-recursion-queries' quota to validator
  queries, but the counter was never actually passed on to
  'dns_resolver_createfetch()'. This has been fixed, and the global
  query counter ('max-query-count', per client request) is now also
  added.

  Related to #4980 :gl:`!9856`

Bug Fixes
~~~~~~~~~

- Accept resolv.conf with more than 8 search domains. ``eda02dc3424``

  :gl:`#1259` :gl:`!2446`

- Fix nsupdate hang when processing a large update. ``fa56e0d8b10``

  To mitigate DNS flood attacks over a single TCP connection, we
  throttle the connection when the other side does not read the data.
  Throttling should only occur on server-side sockets, but erroneously
  also happened for nsupdate, which acts as a client. When nsupdate
  started throttling the connection, it never attempts to read again.
  This has been fixed.   :gl:`#4910` :gl:`!9709`

- Lock and attach when returning zone stats. ``3c720c64250``

  When returning zone statistics counters, the statistics sets are now
  attached while the zone is locked.  This addresses Coverity warnings
  CID 468720, 468728 and 468729. :gl:`#4934` :gl:`!9488`

- Fix possible assertion failure when reloading server while processing
  updates. ``be5266a7c61``

  :gl:`#5006` :gl:`!9745`

- Preserve cache across reconfig when using attach-cache.
  ``0b287f3aaf9``

  When the `attach-cache` option is used in the `options` block with an
  arbitrary name, it causes all views to use the same cache. Previously,
  this configuration caused the cache to be deleted and a new cache
  created every time the server was reconfigured. This has been fixed.
  :gl:`#5061` :gl:`!9787`

- Resolve the spurious drops in performance due GLUE cache.
  ``e2c1941efd2``

  For performance reasons, the returned GLUE records are cached on the
  first use.  The current implementation could randomly cause a
  performance drop and increased memory use.  This has been fixed.
  :gl:`#5064` :gl:`!9831`

- Fix dnssec-signzone signing non-DNSKEY RRsets with revoked keys.
  ``1435770b1a7``

  `dnssec-signzone` was using revoked keys for signing RRsets other than
  DNSKEY.  This has been corrected. :gl:`#5070` :gl:`!9800`

- Disable deterministic ecdsa for fips builds. ``707dded9798``

  FIPS 186-5 [1] allows the usage deterministic ECDSA (Section 6.3)
  which is compabile with RFC 6979 [2] but OpenSSL seems to follow FIPS
  186-4 (Section 6.3) [3] which only allows for random k values, failing
  k value generation for OpenSSL >=3.2. [4]

  Fix signing by not using deterministic ECDSA when FIPS mode is active.

  [1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf [2]:
  https://datatracker.ietf.org/doc/html/rfc6979 [3]:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf [4]: https:
  //github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b
  1e64/crypto/ec/ecdsa_ossl.c#L201-L207 :gl:`#5072` :gl:`!9808`

- Revert "Lock and attach when returning zone stats" ``de6f199f4d2``

  :gl:`#5082` :gl:`!9859`

- Unknown directive in resolv.conf not handled properly. ``48901ef57e7``

  The line after an unknown directive in resolv.conf could accidentally
  be skipped, potentially affecting dig, host, nslookup, nsupdate, or
  delv. This has been fixed. :gl:`#5084` :gl:`!9865`

- Querying an NSEC3-signed zone for an empty record could trigger an
  assertion. ``3a94afa03a1``

  A bug in the qpzone database could trigger a crash when querying for a
  deleted name, or a newly-added empty non-terminal name, in an
  NSEC3-signed zone. This has been fixed. :gl:`#5108` :gl:`!9928`

- Fix response policy zones and catalog zones with an $INCLUDE statement
  defined. ``19a2aab136a``

  Response policy zones (RPZ) and catalog zones were not working
  correctly if they had an $INCLUDE statement defined. This has been
  fixed. :gl:`#5111` :gl:`!9930`

- Clean up incorrect logging module names. ``3db39ec7ad5``

  Some files used logmodule names that had been copied in from
  elsewhere; these have now been given module names of their own. Also,
  the RBT and RBTDB logmodules have been removed, since they are now
  unused. :gl:`!9895`

- Finalize removal of memory debug flags size and mctx. ``667383587b2``

  Commit 4b3d0c66009d30f5c0bc12ee128fc59f1d853f44 has removed them, but
  did not remove few traces in documentation and help. Remove them from
  remaining places. :gl:`!9606`

- Mark loop as shuttingdown earlier in shutdown_cb. ``d71869d6a78``

  :gl:`!9827`

- Use CMM_{STORE,LOAD}_SHARED to store/load glue in gluelist.
  ``6ce55429f14``

  ThreadSanitizer has trouble understanding that gluelist->glue is
  constant after it is assigned to the slabheader with cmpxchg.  Help
  ThreadSanitizer to understand the code by using CMM_STORE_SHARED and
  CMM_LOAD_SHARED on gluelist->glue. :gl:`!9929`


