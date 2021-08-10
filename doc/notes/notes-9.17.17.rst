.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.17
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fixed an assertion failure that occurred in ``named`` when it
  attempted to send a UDP packet that exceeded the MTU size, if
  Response Rate Limiting (RRL) was enabled. (CVE-2021-25218) :gl:`#2856`

- ``named`` failed to check the opcode of responses when performing zone
  refreshes, stub zone updates, and UPDATE forwarding. This could lead
  to an assertion failure under certain conditions and has been
  addressed by rejecting responses whose opcode does not match the
  expected value. :gl:`#2762`

New Features
~~~~~~~~~~~~

- DNS-over-HTTPS (DoH) support can now be disabled at compile time using
  a new build-time option, ``--disable-doh``. This allows BIND 9 to be
  built without the libnghttp2 library. :gl:`#2478`

- It is now possible to set a hard quota on both the number of
  concurrent DNS-over-HTTPS (DoH) connections and the number of active
  HTTP/2 streams per connection, by using the ``http-listener-clients``
  and ``http-streams-per-connection`` options, or the
  ``listener-clients`` and ``streams-per-connection`` parameters in an
  ``http`` statement. The defaults are 300 and 100, respectively.
  :gl:`#2809`

Feature Changes
~~~~~~~~~~~~~~~

- Previously, ``named`` accepted FORMERR responses both with and without
  an OPT record, as an indication that a given server did not support
  EDNS. To implement full compliance with :rfc:`6891`, only FORMERR
  responses without an OPT record are now accepted. This intentionally
  breaks communication with servers that do not support EDNS and that
  incorrectly echo back the query message with the RCODE field set to
  FORMERR and the QR bit set to 1. :gl:`#2249`

- Memory allocation has been substantially refactored; it is now based
  on the memory allocation API provided by the jemalloc library, on
  platforms where it is available. Use of this library is now
  recommended when building BIND 9; although it is optional, it is
  enabled by default. :gl:`#2433`

- Testing revealed that setting the thread affinity for various types of
  ``named`` threads led to inconsistent recursive performance, as
  sometimes multiple sets of threads competed over a single resource.

  Due to the above, ``named`` no longer sets thread affinity. This
  causes a slight dip of around 5% in authoritative performance, but
  recursive performance is now consistently improved. :gl:`#2822`

- CDS and CDNSKEY records can now be published in a zone without the
  requirement that they exactly match an existing DNSKEY record, as long
  as the zone is signed with an algorithm represented in the CDS or
  CDNSKEY record. This allows a clean rollover from one DNS provider to
  another when using a multiple-signer DNSSEC configuration. :gl:`#2710`

Bug Fixes
~~~~~~~~~

- Authentication of ``rndc`` messages could fail if a ``controls``
  statement was configured with multiple key algorithms for the same
  listener. This has been fixed. :gl:`#2756`
