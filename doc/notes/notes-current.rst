.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.16
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Sending non-zero opcode via DoT or DoH channels would trigger an assertion
  failure in ``named``. This has been fixed.

  ISC would like to thank Ville Heikkila of Synopsys Cybersecurity Research
  Center for responsibly disclosing the vulnerability to us. :gl:`#2787`

- Named failed to check the opcode of responses when performing refresh,
  stub updates, and UPDATE forwarding.  This could lead to an assertion
  failure under particular conditions.  This has been addressed by checking
  the opcode of those responses and rejecting the messages if they don't
  match the expected value. :gl:`#2762`

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Automatic KSK rollover: A new configuration option ``parental-agents`` is
  added to add a list of servers to a zone that can be used for checking DS
  presence. :gl:`#1126`

- It is now possible to set a hard quota on the number of concurrent DoH
  connections, and the number of active HTTP/2 streams per connection,
  by using the ``http-listener-clients`` and ``http-streams-per-connection``
  options, or the ``listener-clients`` and ``streams-per-connection``
  parameters to an ``http`` statement. The defaults are 300 and 100
  respectively. :gl:`#2809`

Removed Features
~~~~~~~~~~~~~~~~

- Support for compiling and running BIND 9 natively on Windows has been
  completely removed.  The last release branch that has working Windows
  support is BIND 9.16. :gl:`#2690`

Feature Changes
~~~~~~~~~~~~~~~

- IP fragmentation on outgoing UDP sockets has been disabled.  Errors from
  sending DNS messages larger than the specified path MTU are properly handled;
  ``named`` now sends back empty DNS messages with the TC (TrunCated) bit set,
  forcing the DNS client to fall back to TCP.  :gl:`#2790`

- DNS over HTTPS support can be disabled at the compile time via the new
  configuration option ``--disable-doh``.  This allows BIND 9 to be
  compiled without libnghttp2 library. :gl:`#2478`

- Memory allocation has been substantially refactored, and is now based on
  the memory allocation API provided by the `jemalloc` library on platforms
  where it is available. This library is now recommended for building BIND 9.
  :gl:`#2433`

- Previously, named accepted FORMERR responses both with and without
  an OPT record, as an indication that a given server did not support
  EDNS. To implement full compliance with RFC 6891, only FORMERR
  responses without an OPT record are now accepted. This intentionally
  breaks communication with servers that do not support EDNS and
  that incorrectly echo back the query message with the RCODE field
  set to FORMERR and the QR bit set to 1. :gl:`#2249`

- CDS and CDNSKEY records may now be published in a zone without the
  requirement that they exactly match an existing DNSKEY record, so long
  the zone is signed with an algorithm represented in the CDS or CDNSKEY
  record.  This allows a clean rollover from one DNS provider to another
  when using a multiple-signer DNSSEC configuration. :gl:`#2710`

Bug Fixes
~~~~~~~~~

- Fixed a bug that caused the NSEC salt to be changed for KASP zones on
  every startup. :gl:`#2725`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`

- A deadlock at startup was introduced when fixing :gl:`#1875` because when
  locking key files for reading and writing, "in-view" logic was not taken into
  account. This has been fixed. :gl:`#2783`

- Fix a race condition where two threads are competing for the same set of key
  file locks, that could lead to a deadlock. This has been fixed. :gl:`#2786`

- Testing revealed that setting the thread affinity on both the netmgr
  and netthread threads led to inconsistent recursive performance, as
  sometimes the netmgr and netthread threads competed over a single
  resource.

  When the affinity is not set, tests show a slight dip in the authoritative
  performance of around 5% (ranging from 3.8% to 7.8%), but
  the recursive performance is now consistently improved. :gl:`#2822`
