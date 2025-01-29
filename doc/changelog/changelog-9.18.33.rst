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

BIND 9.18.33
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2024-12705] DNS-over-HTTP(s) flooding fixes. ``e733e624147``

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
  ``c6e6a7af8ac``

  When answering queries, don't add data to the additional section if
  the answer has more than 13 names in the RDATA. This limits the number
  of lookups into the database(s) during a single client query, reducing
  query processing load. :gl:`#5034`

New Features
~~~~~~~~~~~~

- Add a new option to configure the maximum number of outgoing queries
  per client request. ``64b2b6edffa``

  The configuration option 'max-query-count' sets how many outgoing
  queries per client request is allowed. The existing
  'max-recursion-queries' is the number of permissible queries for a
  single name and is reset on every CNAME redirection. This new option
  is a global limit on the client request. The default is 200.

  This allows us to send a bit more queries while looking up a single
  name. The default for 'max-recursion-queries' is changed from 32 to
  50. :gl:`#4980`  :gl:`#4921` :gl:`!9847`

Feature Changes
~~~~~~~~~~~~~~~

- Update picohttpparser.{c,h} with upstream repository. ``326b445e469``

  :gl:`#4485` :gl:`!9864`

- Remove unused maxquerycount. ``c30067bb2f3``

  Related to #4980 :gl:`!9854`

- Use query counters in validator code. ``b1207ea9ed6``

  Commit af7db8951364a89c468eda1535efb3f53adc2c1f as part of #4141 was
  supposed to apply the 'max-recursion-queries' quota to validator
  queries, but the counter was never actually passed on to
  'dns_resolver_createfetch()'. This has been fixed, and the global
  query counter ('max-query-count', per client request) is now also
  added.

  Related to #4980 :gl:`!9867`

Bug Fixes
~~~~~~~~~

- Fix nsupdate hang when processing a large update. ``9a0588f7cf2``

  To mitigate DNS flood attacks over a single TCP connection, we
  throttle the connection when the other side does not read the data.
  Throttling should only occur on server-side sockets, but erroneously
  also happened for nsupdate, which acts as a client. When nsupdate
  started throttling the connection, it never attempts to read again.
  This has been fixed.   :gl:`#4910` :gl:`!9835`

- Fix possible assertion failure when reloading server while processing
  updates. ``1d4e60c9ba9``

  :gl:`#5006` :gl:`!9821`

- Fix dnssec-signzone signing non-DNSKEY RRsets with revoked keys.
  ``bf2f4d4aad8``

  `dnssec-signzone` was using revoked keys for signing RRsets other than
  DNSKEY.  This has been corrected. :gl:`#5070` :gl:`!9841`

- Unknown directive in resolv.conf not handled properly. ``75ae186fa1f``

  The line after an unknown directive in resolv.conf could accidentally
  be skipped, potentially affecting dig, host, nslookup, nsupdate, or
  delv. This has been fixed. :gl:`#5084` :gl:`!9878`

- Fix a bug in isc_rwlock_trylock() ``f68e60b3dc4``

  When isc_rwlock_trylock() fails to get a read lock because another
  writer was faster, it should wake up other waiting writers in case
  there are no other readers, but the current code forgets about the
  currently active writer when evaluating 'cntflag'.

  Unset the WRITER_ACTIVE bit in 'cntflag' before checking to see if
  there are other readers, otherwise the waiting writers, if they exist,
  might not wake up. :gl:`#5121` :gl:`!9937`


