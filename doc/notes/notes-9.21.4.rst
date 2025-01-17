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

- Add Extended DNS Error Code 22 - No Reachable Authority.

  When the resolver is trying to query an authoritative server and
  eventually times out, a SERVFAIL answer is given to the client. Add
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

  The configuration option :any:`max-query-count` sets how many outgoing
  queries per client request are allowed. The existing
  :any:`max-recursion-queries` value is the number of permissible queries for a
  single name and is reset on every CNAME redirection. This new option
  is a global limit on the client request. The default is 200.

  The default for :any:`max-recursion-queries` is changed from 32 to
  50. This allows :any:`named` to send a few more queries
  while looking up a single name. :gl:`#4980` :gl:`#4921`

- Use the Server Name Indication (SNI) extension for all outgoing TLS
  connections.

  This improves compatibility with other DNS server software.
  :gl:`#5099`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the ``dnssec-must-be-secure`` feature. :gl:`#4482`

- Remove ``sortlist`` option.

  The ``sortlist`` option, which was deprecated in BIND 9.20, has now been
  removed. :gl:`#4665`

- Remove support for fixed RRset ordering.

  Remove the ``fixed`` value from the :any:`rrset-order` option and the
  ``--enable-fixed-rrset`` option from the ``./configure`` script.
  :gl:`#4666`

- Remove ``trusted-keys`` and ``managed-keys`` options.

  These options have been deprecated in 9.19 in favor of the
  :any:`trust-anchors` option and are now being removed. :gl:`#5080`

Feature Changes
~~~~~~~~~~~~~~~

- The configuration clauses ``parental-agents`` and ``primaries`` are renamed to
  :any:`remote-servers`.

  The top blocks ``primaries`` and ``parental-agents`` are no longer
  preferred and should be renamed to :any:`remote-servers`. The zone
  statements :any:`parental-agents` and :any:`primaries` are still used, and may
  refer to any :any:`remote-servers` top block. :gl:`#4544`

Bug Fixes
~~~~~~~~~

- Querying an NSEC3-signed zone for an empty record could trigger an
  assertion.

  A bug in the qpzone database could trigger a crash when querying for a
  deleted name, or a newly added empty non-terminal name, in an
  NSEC3-signed zone. This has been fixed. :gl:`#5108`

- Fix :iscman:`nsupdate` hang when processing a large update.

  To mitigate DNS flood attacks over a single TCP connection, throttle
  the connection when the other side does not read the data. Throttling
  should only occur on server-side sockets, but erroneously also
  happened for :iscman:`nsupdate`, which acts as a client. When
  :iscman:`nsupdate` started throttling the connection, it never
  attempted to read again. This has been fixed. :gl:`#4910`

- Fix possible assertion failure when reloading server while processing
  update policy rules. :gl:`#5006`

- Preserve cache across reconfig when using :any:`attach-cache`.

  When the :any:`attach-cache` option is used in the ``options`` block with an
  arbitrary name, it causes all views to use the same cache. Previously,
  this configuration caused the cache to be deleted and a new cache
  to be created every time the server was reconfigured. This has been fixed.
  :gl:`#5061`

- Resolve the spurious drops in performance due to glue cache.

  For performance reasons, the returned glue records are cached on the
  first use.  The current implementation could randomly cause a
  performance drop and increased memory use.  This has been fixed.
  :gl:`#5064`

- Fix :iscman:`dnssec-signzone` signing non-DNSKEY RRsets with revoked keys.

  :any:`dnssec-signzone` was using revoked keys for signing RRsets other than
  DNSKEY.  This has been corrected. :gl:`#5070`

- Disable deterministic ECDSA for FIPS builds.

  `FIPS 186-5 <https://csrc.nist.gov/pubs/fips/186-5/final>`_ allows use
  of deterministic ECDSA (Section 6.3), which is compatible with
  :rfc:`6979`, but OpenSSL seems to follow `FIPS 186-4
  <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>`_
  (Section 6.3), which only allows random ``k`` values. This causes ``k``
  value generation to fail for OpenSSL >= 3.2, making BIND unable to
  generate ECDSA signatures when in FIPS mode.

  This signing is now fixed by not using deterministic ECDSA when FIPS mode is active. :gl:`#5072`

- Fix improper handling of unknown directives in ``resolv.conf``.

  The line after an unknown directive in ``resolv.conf`` could accidentally be
  skipped, potentially affecting :iscman:`dig`, :iscman:`host`,
  :iscman:`nslookup`, :iscman:`nsupdate`, or :iscman:`delv`. This has been
  fixed. :gl:`#5084`

- Fix response policy zones and catalog zones with an ``$INCLUDE`` statement
  defined.

  Response policy zones (RPZ) and catalog zones were not working
  correctly if they had an ``$INCLUDE`` statement defined. This has been
  fixed. :gl:`#5111`


