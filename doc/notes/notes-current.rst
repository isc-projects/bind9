.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.20
----------------------

Security Fixes
~~~~~~~~~~~~~~

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

- None.

- Add support for HTTPS and SVCB record types. :gl:`#1132`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- CDS and CDNSKEY records may now be published in a zone without the
  requirement that they exactly match an existing DNSKEY record, so long
  the zone is signed with an algorithm represented in the CDS or CDNSKEY
  record.  This allows a clean rollover from one DNS provider to another
  when using a multiple-signer DNSSEC configuration. :gl:`#2710`

- ``dnssec-signzone`` is now able to retain signatures from inactive
  predecessor keys without introducing additional signatures from the successor
  key. This allows for a gradual replacement of RRSIGs as they reach expiry.
  :gl:`#1551`

Bug Fixes
~~~~~~~~~

- Testing revealed that setting the thread affinity on both the netmgr
  and netthread threads led to inconsistent recursive performance, as
  sometimes the netmgr and netthread threads competed over a single
  resource.

  When the affinity is not set, tests show a slight dip in the authoritative
  performance of around 5% (ranging from 3.8% to 7.8%), but
  the recursive performance is now consistently improved. :gl:`#2822`

- When following QNAME minimization, BIND could use a stale zonecut from cache 
  to resolve the query, resulting in a non-minimized query. This has been
  fixed :gl:`#2665`
