.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.9
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- A new configuration option ``stale-refresh-time`` has been introduced, it
  allows stale RRset to be served directly from cache for a period of time
  after a failed lookup, before a new attempt to refresh it is made. [GL #2066]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Handle `UV_EOF` differently such that it is not treated as a `TCP4RecvErr` or
  `TCP6RecvErr`. [GL #2208]

- ``named`` could crash with an assertion failure if a TCP connection is closed
  while the request is still processing. [GL #2227]
