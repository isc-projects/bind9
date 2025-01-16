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

Notes for BIND 9.20.5
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

Feature Changes
~~~~~~~~~~~~~~~

- The configuration clauses parental-agents and primaries are renamed to
  remote-servers.

  The top blocks 'primaries' and 'parental-agents' are no longer
  preferred and should be renamed to 'remote-servers'. The zone
  statements 'parental-agents' and 'primaries' are still used, and may
  refer to any 'remote-servers' top block. :gl:`#4544`

- Add none parameter to query-source and query-source-v6 to disable IPv4
  or IPv6 upstream queries.

  Add a none parameter to named configuration option `query-source`
  (respectively `query-source-v6`) which forbid usage of IPv4
  (respectively IPv6) addresses when named is doing an upstream query.
  :gl:`#4981` Turning-off upstream IPv6 queries while still listening to
  downstream queries on IPv6.

- Revert "Fix NSEC3 closest encloser lookup for names with empty
  non-terminals"

  Revert the fix for #4950 for 9.20.

  This reverts MR !9438.

  History: A performance improvement for NSEC3 closest encloser lookups
  (#4460) was introduced (in MR !9436) and backported to 9.20 (MR !9438)
  and to 9.18 in (MR !9439). It was released in 9.18.30 (and 9.20.2 and
  9.21.1).

  There was a bug in the code (#4950), so we reverted the change in
  !9611, !9613 and !9614 (not released).

  Then a new attempt was merged in main (MR !9610) and backported to
  9.20 (MR !9631) and 9.18 (MR !9632). The latter should not have been
  backported and was reverted in !9689.

  We now also revert the fix for 9.20 :gl:`#5108`

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

- Unknown directive in resolv.conf not handled properly.

  The line after an unknown directive in resolv.conf could accidentally
  be skipped, potentially affecting dig, host, nslookup, nsupdate, or
  delv. This has been fixed. :gl:`#5084`

- Fix response policy zones and catalog zones with an $INCLUDE statement
  defined.

  Response policy zones (RPZ) and catalog zones were not working
  correctly if they had an $INCLUDE statement defined. This has been
  fixed. :gl:`#5111`


