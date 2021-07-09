.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.19
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

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

- Using a new configuration option, ``parental-agents``, each zone can
  now be associated with a list of servers that can be used to check the
  DS RRset in the parent zone. This enables automatic KSK rollovers.
  :gl:`#1126`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- IP fragmentation has been disabled for outgoing UDP sockets. Errors
  triggered by sending DNS messages larger than the specified path MTU
  are properly handled by sending empty DNS replies with the ``TC``
  (TrunCated) bit set, which forces DNS clients to fall back to TCP.
  :gl:`#2790`

- CDS and CDNSKEY records may now be published in a zone without the
  requirement that they exactly match an existing DNSKEY record, so long
  the zone is signed with an algorithm represented in the CDS or CDNSKEY
  record.  This allows a clean rollover from one DNS provider to another
  when using a multiple-signer DNSSEC configuration. :gl:`#2710`

Bug Fixes
~~~~~~~~~

- The code managing :rfc:`5011` trust anchors created an invalid
  placeholder keydata record upon a refresh failure, which prevented the
  database of managed keys from subsequently being read back. This has
  been fixed. :gl:`#2686`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`

- A bug that caused the NSEC3 salt to be changed on every restart for
  zones using KASP has been fixed. :gl:`#2725`

- The configuration-checking code failed to account for the inheritance
  rules of the ``dnssec-policy`` option. This has been fixed.
  :gl:`#2780`

- The fix for :gl:`#1875` inadvertently introduced a deadlock: when
  locking key files for reading and writing, the ``in-view`` logic was
  not considered. This has been fixed. :gl:`#2783`

- A race condition could occur where two threads were competing for the
  same set of key file locks, leading to a deadlock. This has been
  fixed. :gl:`#2786`

- Testing revealed that setting the thread affinity on both the netmgr
  and netthread threads led to inconsistent recursive performance, as
  sometimes the netmgr and netthread threads competed over a single
  resource.

  When the affinity is not set, tests show a slight dip in the authoritative
  performance of around 5% (ranging from 3.8% to 7.8%), but
  the recursive performance is now consistently improved. :gl:`#2822`
