.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.11
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

- A new option, ``purge-keys``, has been added to ``dnssec-policy``. It sets
  the time how long key files should be retained after they have become
  obsolete (due to a key rollover). Default is 90 days, and the feature can
  be disabled by setting it to 0. [GL #2408]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- If an invalid key name (e.g. "a..b") was specified in a ``primaries``
  list in ``named.conf``, the wrong size was passed to ``isc_mem_put()``,
  which resulted in the returned memory being put on the wrong freed
  list. This has been fixed. [GL #2460]

- If an outgoing packet would exceed max-udp-size, it would be dropped instead
  of sending a proper response back.  Rollback setting the IP_DONTFRAG on the
  UDP sockets that we enabled during the DNS Flag Day 2020 to fix this issue.
  [GL #2487]

- An invalid direction field (not one of 'N'/'S' or 'E'/'W') in a LOC record
  triggered an INSIST failure. [GL #2499]
