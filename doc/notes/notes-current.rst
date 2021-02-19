.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.13
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- When serve-stale is enabled and stale data is available, ``named`` now
  returns stale answers upon encountering any unexpected error in the
  query resolution process. This may happen, for example, if the
  ``fetches-per-server`` or ``fetches-per-zone`` limits are reached. In
  this case, ``named`` attempts to answer DNS requests with stale data,
  but does not start the ``stale-refresh-time`` window. [GL #2434]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- If an outgoing packet would exceed max-udp-size, it would be dropped instead
  of sending a proper response back.  Rollback setting the IP_DONTFRAG on the
  UDP sockets that we enabled during the DNS Flag Day 2020 to fix this issue.
  [GL #2487]

- An invalid direction field (not one of 'N'/'S' or 'E'/'W') in a LOC record
  triggered an INSIST failure. [GL #2499]
