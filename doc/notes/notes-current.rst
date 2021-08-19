.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.18
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Add support for HTTPS and SVCB record types. :gl:`#1132`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- ``dnssec-signzone`` is now able to retain signatures from inactive
  predecessor keys without introducing additional signatures from the successor
  key. This allows for a gradual replacement of RRSIGs as they reach expiry.
  :gl:`#1551`

Bug Fixes
~~~~~~~~~

- When following QNAME minimization, BIND could use a stale zonecut from cache 
  to resolve the query, resulting in a non-minimized query. This has been
  fixed :gl:`#2665`
