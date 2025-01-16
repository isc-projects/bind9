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

Notes for BIND 9.18.33
----------------------

Security Fixes
~~~~~~~~~~~~~~

- DNS-over-HTTPS flooding fixes. :cve:`2024-12705`

  Fix DNS-over-HTTPS implementation issues that arise under heavy
  query load. Optimize resource usage for :iscman:`named` instances that
  accept queries over DNS-over-HTTPS.

  Previously, :iscman:`named` processed all incoming HTTP/2 data at
  once, which could overwhelm the server, especially when dealing with
  clients that sent requests but did not wait for responses. That has been
  fixed. Now, :iscman:`named` handles HTTP/2 data in smaller chunks and
  throttles reading until the remote side reads the response data. It
  also throttles clients that send too many requests at once.

  In addition, :iscman:`named` now evaluates excessive streams opened by
  clients that include no DNS data, which is considered "flooding." It
  logs these clients and drops connections from them. :gl:`#4795`

  In some cases, :iscman:`named` could leave DNS-over-HTTPS
  connections in the `CLOSE_WAIT` state indefinitely. That has also been
  fixed. :gl:`#5083`

  ISC would like to thank Jean-François Billaud for his assistance with
  investigating this issue.

- Limit additional section processing for large RDATA sets.
  :cve:`2024-11187`

  When answering queries, don't add data to the additional section if
  the answer has more than 13 names in the RDATA. This limits the number
  of lookups into the database(s) during a single client query, reducing
  the query-processing load. :gl:`#5034`

  ISC would like to thank Toshifumi Sakaguchi for bringing this
  vulnerability to our attention.

New Features
~~~~~~~~~~~~

- Add a new option to configure the maximum number of outgoing queries
  per client request.

  The configuration option :any:`max-query-count` sets how many outgoing
  queries per client request are allowed. The existing
  :any:`max-recursion-queries` value is the number of permissible queries for a
  single name and is reset on every CNAME redirection. This new option
  is a global limit on the client request. The default is 200.

  The default for :any:`max-recursion-queries` is changed from 32 to
  50. This allows :any:`named` to send a few more queries
  while looking up a single name. :gl:`#4980` :gl:`#4921`

Bug Fixes
~~~~~~~~~

- Fix :iscman:`nsupdate` hang when processing a large update.

  To mitigate DNS flood attacks over a single TCP connection, throttle
  the connection when the other side does not read the data. Throttling
  should only occur on server-side sockets, but erroneously also
  happened for :iscman:`nsupdate`, which acts as a client. When
  :iscman:`nsupdate` started throttling the connection, it never
  attempted to read again. This has been fixed. :gl:`#4910`

- Fix possible assertion failure when reloading server while processing
  update policy rules. :gl:`#5006`

- Fix :iscman:`dnssec-signzone` signing non-DNSKEY RRsets with revoked keys.

  :any:`dnssec-signzone` was using revoked keys for signing RRsets other than
  DNSKEY.  This has been corrected. :gl:`#5070`

- Fix improper handling of unknown directives in ``resolv.conf``.

  The line after an unknown directive in ``resolv.conf`` could accidentally be
  skipped, potentially affecting :iscman:`dig`, :iscman:`host`,
  :iscman:`nslookup`, :iscman:`nsupdate`, or :iscman:`delv`. This has been
  fixed. :gl:`#5084`



