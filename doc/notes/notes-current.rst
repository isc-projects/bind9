.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.6
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- The ``dig``, ``host``, and ``nslookup`` tools have been converted to
  use the new network manager API rather than the older ISC socket API.

  As a side effect of this change, the ``dig +unexpected`` option no longer
  works.  This could previously be used for diagnosing broken servers or
  network configurations by listening for replies from servers other than
  the one that was queried.  With the new API such answers are filtered
  before they ever reach ``dig``.  Consequently, the option has been
  removed. [GL #2140]

Bug Fixes
~~~~~~~~~

- Handle `UV_EOF` differently such that it is not treated as a `TCP4RecvErr` or
  `TCP6RecvErr`. [GL #2208]

- ``named`` could crash with an assertion failure if a TCP connection is closed
  while the request is still processing. [GL #2227]
