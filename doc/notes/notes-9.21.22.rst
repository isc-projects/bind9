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

Notes for BIND 9.21.22
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix outgoing zone transfers' quota issue.

  Unauthorized clients could consume outgoing zone transfers quota and
  block authorized zone transfer clients. This has been fixed.
  :gl:`#3589`

- [CVE-2026-3592] Limit resolver server list size.

  When resolving a domain with many nameservers that share overlapping
  IP addresses (e.g., 10 NS records all pointing at the same set of
  addresses), BIND could previously waste time querying duplicate
  addresses and build up excessively large server lists.  Deduplicate
  addresses in the resolver's server list so that each unique IP is only
  queried once per resolution attempt, regardless of how many NS records
  point to it and cap the number of addresses stored per nameserver name
  to 6 (combined A and AAAA), preventing memory and CPU overhead from
  domains with unusually large NS/glue sets. :gl:`#5641`

- [CVE-2026-3039] Fix GSS-API resource leak.

  Fixed a memory leak where each GSS-API TKEY negotiation leaked a
  security context inside the GSS library. An unauthenticated attacker
  could exhaust server memory by sending repeated TKEY queries to a
  server with tkey-gssapi-keytab configured. The leaked memory was
  allocated by the GSS library, bypassing BIND's memory accounting.

  Multi-round GSS-API negotiation (GSS_S_CONTINUE_NEEDED) is now
  rejected, as BIND never supported it correctly and Kerberos/SPNEGO
  completes in a single round. :gl:`#5752`

- [CVE-2026-5946] Disable recursion, UPDATE, and NOTIFY for non-IN
  views.

  Recursion, dynamic updates (UPDATE), and zone change notifications
  (NOTIFY) are now disabled for views with a class other than IN (such
  as CHAOS or HESIOD); authoritative service for non-IN zones (e.g.
  version.bind in class CHAOS) continues to work as before. Servers
  configured with recursion yes in a non-IN view will log a warning at
  startup, and named-checkconf flags the same condition. UPDATE and
  NOTIFY messages that specify the meta-classes ANY or NONE in the
  question section are now rejected with FORMERR.

  This addresses a set of closely related security issues collectively
  identified as CVE-2026-5946. ISC would like to thank Mcsky23 for
  bringing these issues to our attention. :gl:`#5784`

- [CVE-2026-5950] Avoid unbounded recursion loop.

  A bug during bad server handling could cause the resolver to enter an
  infinite loop, continuously sending queries to an upstream server with
  no exit condition, until the resolver query timeout was hit. This has
  been fixed.

  ISC would like to thank Billy Baraja (BielraX) for bringing this issue
  to our attention. :gl:`#5804`

- [CVE-2026-5947] Fix crash in resolver when SIG(0)-signed responses are
  received under load.

  A resolver could crash when handling a SIG(0)-signed response if the
  matching client query was cancelled while signature verification was
  still in progress — for example, when the recursive-clients quota was
  exhausted. This has been fixed. :gl:`#5819`

- Fix race condition in getsigningtime()

  Compute qpzone_get_lock(elem->node) into a local variable while the
  heap lock is still held, rather than dereferencing the stale elem
  pointer after releasing the lock. A concurrent thread running
  setsigningtime() (e.g. via IXFR apply on a worker thread) could free
  the top-of-heap element between the heap lock release and the
  dereference, causing a use-after-free. :gl:`#5883`

- [CVE-2026-3593] Fix use-after-free in DNS-over-HTTPS when processing
  HTTP/2 SETTINGS frames.

  A use-after-free vulnerability in the DNS-over-HTTPS implementation
  could cause named to crash when a client sends a flood of HTTP/2
  SETTINGS frames while a DoH response is being written. This affects
  servers with DoH (DNS-over-HTTPS) enabled.

  ISC would like to thank Naresh Kandula Parmar (Nottiboy) for reporting
  this.

  For: #5755

Feature Changes
~~~~~~~~~~~~~~~

- Fix CPU spikes and slow queries when cache approaches memory limit.

  Spread cache cleanup probabilistically to avoid CPU usage spikes and a
  drop in query throughput. :gl:`#5891`

- Document that named-checkzone must not run on untrusted input.

  The zone-file parser implements $INCLUDE by opening whatever local
  path the zone text names, and fragments of the included file leak
  through parser error messages. There is no safe way to validate
  untrusted zone text with named-checkzone or named-compilezone, so the
  manual pages for both tools now warn against doing so.

- Implement RFC 3645 Section 4.1.1 key expiry check in TKEY.

  Check for existing TSIG keys before accepting a new GSS-API
  negotiation and delete the key if it has expired. Previously, an
  expired GSS key would permanently block re-negotiation for that name
  until the server was restarted.

- Reduce memory footprint by actively returning unused memory to the OS.

  Previously, :iscman:`named` relied on the default allocator settings
  for releasing unused memory back to the operating system, which could
  result in unnecessarily high resident memory usage. :iscman:`named`
  now actively manages memory page purging. On systems using jemalloc,
  background cleanup threads are enabled and the dirty page decay time
  is reduced from 10 seconds to 5 seconds. Additionally, a volume-based
  decay pass is triggered after every 16 MiB of freed memory.  On
  glibc-based systems, a similar volume-based mechanism using
  malloc_trim() is used instead.

Bug Fixes
~~~~~~~~~

- Use the zone file's basename as origin in DNSSEC tools.

  In `dnssec-signzone` and `dnssec-verify`, when the zone origin is not
  specified using the `-o` parameter, the default behavior is to try to
  sign using the zone's file name as the origin. So, for example,
  `dnssec-signzone -S example.com` will work, so long as the file name
  matches the zone name.

  This now also works if the zone is in a different directory. For
  example, `dnssec-signzone -S zones/example.com` will set the origin
  value to `example.com`. :gl:`#5678`

- Fix a possible race condition during zone transfers.

  The :iscman:`named` process could terminate unexpectedly when
  processing an IXFR message during a zone transfer. This has been
  fixed. :gl:`#5767`

- Do not resend query after BADCOOKIE answer on TCP.

  When an upstream server answers BADCOOKIE, no matter which transport
  is used, the resolver resends the query using TCP. However, if the
  upstream server responded with BADCOOKIE again over TCP, the resolver
  would keep resending until the maximum query count was reached.

  This is now fixed by no longer resending once the query has already
  been sent over TCP. :gl:`#5804`

- Fix named crash when processing SIG records in dynamic updates.

  Previously, :iscman:`named` could abort if a client sent a dynamic
  update containing a SIG record (the legacy signature type) to a zone
  configured with an update-policy. The function `dns_db_findrdataset`
  had an incorrect requirements prerequisite that prevented SIG records
  being looked up, which was triggered as part of processing an UPDATE
  request and could be triggered remotely by any client permitted to
  send updates. This has been fixed by ensuring that SIG records are
  handled consistently with RRSIG records during update processing.
  :gl:`#5818`

- Fix wrong NSEC proof for empty non-terminals after IXFR.

  When a secondary received an IXFR that transitioned a zone from
  unsigned to NSEC-signed, queries for empty non-terminal names returned
  the zone apex NSEC record instead of the NSEC that actually covers the
  queried name.  The issue only occurred with incremental transfers; a
  full AXFR or a server restart resolved it. :gl:`#5824`

- Fix rndc modzone behavior for a zone in named.conf.

  If a zone was present in the configuration file and not originally
  added by `rndc addzone`, `rndc modzone` for that zone would succeed
  once but subsequent `modzone` attempts would fail. This has been
  fixed. :gl:`#5826`

- Fix zone verification of NSEC3 signed zones.

  Previously, when computing the compressed bitmap during verification
  of an NSEC3-signed zone, an undersized buffer was used that resulted
  in an out-of-bounds write if there were too many active windows in the
  bitmap. This impacted mirror zones which are NSEC3-signed,
  `dnssec-signzone` and `dnssec-verifyzone`. This has been fixed.
  :gl:`#5834`

- Fix 'rndc modzone' issue with non-existing zones.

  The :iscman:`named` process could terminate unexpectedly or become
  subject to undefined behavior when issued an :option:`rndc modzone`
  operation for a non-existing zone. This has been fixed. :gl:`#5848`

- Fix zone filename token-parsing bug.

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog member zone containing special characters like
  '%' or '$' which could be interpreted as zone filename tokens and
  trigger a case-sensitivity bug in the token-parsing code. This has
  been fixed. :gl:`#5849`

- Prevent a crash when using both dns64 and filter-aaaa.

  An assertion failure could be triggered if both `dns64` and the
  `filter-aaaa` plugin were in use simultaneously. This happened if the
  plugin triggered a second recursion process, which then attempted to
  store DNS64 state information in a pointer that had already been set
  by the original recursion process. This has been fixed. :gl:`#5854`

- Remove unnecessary dns_name_free call.

  When processing a catalog zone member's primaries definition and there
  is a TXT record containing an invalid name TSIG key name,
  dns_name_free was incorrectly called triggering an assertion. This has
  been fixed. :gl:`#5858`

- Prevent malicious DNSSEC zones from exhausting validator CPU.

  A DNSSEC-signed zone could publish a DNSKEY with an unusually large
  RSA public exponent and force any validator resolving names in that
  zone to spend disproportionate CPU verifying signatures.  The
  validator now rejects such DNSKEYs, matching the limit already applied
  to keys read from files or HSMs. :gl:`#5881`

- Fix rndc-confgen aborting on HMAC-SHA-384/512 keys above 512 bits.

  `rndc-confgen -A hmac-sha384` and `-A hmac-sha512` documented a `-b`
  range of 1..1024, but any value above 512 aborted on hardened builds
  instead of producing a key. The full advertised range now works.
  :gl:`#5903`

- Validate key names in rndc-confgen, tsig-keygen, ddns-confgen.

  The three tools embedded the key-name argument verbatim into the
  generated `named.conf` block, so a name containing characters like
  `"`, `{`, or `;` produced output that did not match the intended `key`
  clause. Key names are now restricted to letters, digits, dots,
  hyphens, and underscores. :gl:`#5904`

- Prevent crafted queries from degrading RRL performance.

  With response rate limiting enabled, an attacker sending queries from
  many spoofed source addresses could steer entries into the same slot
  of the internal rate-limit table and slow down query processing on the
  affected server. The table now uses a per-process keyed hash so the
  placement of entries cannot be predicted or influenced from the
  network. :gl:`#5906`

- Prevent rare named crash when notifies are cancelled.

  Under heavy load, named could occasionally crash when a queued
  outbound notify or zone refresh was cancelled at the moment it was
  being sent — for example, while a zone was being reloaded or removed.
  The race that caused the crash is now prevented. :gl:`#5915`

- Stop delv from aborting on a malformed query name.

  delv aborts with SIGABRT instead of exiting cleanly when given a query
  name that fails wire-format conversion (e.g. a label longer than 63
  octets). After this change delv prints the parse error and exits with
  a normal failure code. :gl:`#5916`

- Fix dig -x crash on excessively long arguments.

  dig -x crashed with a segmentation fault rather than printing an error
  when given an argument with thousands of dot-separated components. dig
  -x now rejects such inputs cleanly with "Invalid IP address".
  :gl:`#5917`

- Reject negative and out-of-range TTLs in dnssec-* tools.

  The dnssec-* tools accepted negative and out-of-range values for TTL
  flags such as dnssec-keygen -L, dnssec-signzone -t and dnssec-settime
  -L, silently turning them into TTLs of around 136 years in the
  resulting key or zone files. The flag values are now validated and
  rejected with a clear "TTL must be non-negative" or "TTL out of range"
  error. :gl:`#5923`

- Fix a crash when reconfiguring while an NTA is being rechecked.

  When named was reconfigured or shut down while a negative trust anchor
  was being rechecked against authoritative servers, the in-flight
  recheck could outlive the view that owned it and cause `named` to
  crash.  This has been fixed. :gl:`#5938`

- Fix a bug in allow-query/allow-transfer catalog zone custom
  properties.

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog zone with an invalid ``allow-query`` or
  ``allow-transfer`` custom property (i.e. having a non-APL type)
  coexisting with the valid property. This has been fixed. :gl:`#5941`

- Fix a memory leak issue in the catalog zones.

  The :iscman:`named` process could leak small amounts of memory when
  processing a catalog zone entry which had defined custom primary
  servers with TSIG keys using both the regular ``primaries`` custom
  property syntax and the legacy alternative syntax (``masters``) at the
  same time. This has been fixed. :gl:`#5943`

- Avoid extra round trips for DS lookups when the parent delegation is
  already cached.

  DS queries could take two unnecessary extra round trips when the
  resolver sent them to the child zone instead of the parent. The child
  responds with NODATA, forcing a recovery path to rediscover the parent
  delegation even though it was already cached.  The resolver now
  consults its delegation cache before starting DS fetches, sending
  queries directly to the correct parent nameservers and eliminating the
  extra latency.

- Fix suppressed missing-glue check in named-checkzone.

  named-checkzone and named-checkconf -z silently skipped the
  missing-glue check for any NS name that had already triggered an
  extra-AAAA-glue warning, so zones missing required A glue could pass
  validation and be deployed with broken delegations.

- Glues from different parent are rejected.

  The changes making BIND 9 parent-centric !11621 introduced an issue
  where it could be possible, when processing a referral, to use the
  glue to a nameserver which has a different parent than the zonecut.
  For instance:

  AUTHORITY         test.example.           NS      ns.test.example.
  test.example.           NS      ns.foo.example.         test.example.
  NS      ns.bar.                  ADDITIONAL         ns.bar.
  A       1.2.3.4         ns.foo.example.         A       5.6.7.8
  ns.test.example.        A       9.8.7.6

  In such situation, only the glues for `ns.foo.example.` and
  `ns.test.example.` should be used, and the glue from `ns.bar.` must be
  ignored as this is not either a sub-domain or a sibling domain, the
  parent is different (`bar.` instead of `example.`). This is now fixed.

  Sibling glue and cyclic sibling glues are defined in RFC 9471 section
  2.2 and section 2.3.

- Implement seamless outgoing TCP connection reuse.

  The resolver can and will reuse outgoing TCP connections to the same
  host, as recommended by RFC 7766. This prevents a whole class of
  attacks that abuse the fact that establishing a TCP connection is
  expensive and it is fairly easy to deplete the outgoing TCP ports by
  putting them into TIME_WAIT state.

  The number of pipelined queries per connection is capped at 256 to
  limit the impact of a connection drop.

- Possible crash when a resolver validate a static-stub zone.

  A NULL pointer dereference could be made in some circumstances when
  resolving and validating a name under a `static-stub` zone. This is
  now fixed.

- Prevent excessive priming queries to the root servers.

  BIND was sending a priming query to the root servers on nearly every
  recursive lookup instead of only when the cached root information
  expired.  Priming now rearms only after the TTL of the fetched records
  elapses, and the refreshed root NS set is used for query routing until
  the next cycle.

- Reject record sets too large to serve in DNS.

  When BIND was asked to store a record set whose total size exceeds
  what fits in a DNS message, it would allocate memory and build the
  structure, then fail later at response time. Such oversized record
  sets are now rejected at the time of storage with an error, avoiding
  wasted work on data that can never be served.

- Stop rndc-confgen from following symlinks when writing the keyfile.

  When rndc-confgen -a (re)created the rndc control key, it followed a
  symbolic link if one happened to exist at the keyfile path: the
  existence check looked through the link, then the file was truncated,
  its ownership changed, and the key contents written into whatever file
  the link pointed at. rndc-confgen now refuses to follow symbolic links
  at the keyfile path and fails with an error instead, so the wrong file
  can no longer be overwritten by accident.


