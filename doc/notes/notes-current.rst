.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.9
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

- ``ipv4only.arpa`` is now served when ``dns64`` is configured. [GL #385]

- When using the ``unixtime`` or ``date`` method to update the SOA
  serial number, ``named`` and ``dnssec-signzone`` silently fell back to
  the ``increment`` method to prevent the new serial number from being
  smaller than the old serial number (using serial number arithmetics).
  ``dnsssec-signzone`` now prints a warning message, and ``named`` logs
  a warning, when such a fallback happens. [GL #2058]

Bug Fixes
~~~~~~~~~

- Only assign threads to CPUs in the CPU affinity set, so that ``named`` no
  longer attempts to run threads on CPUs outside the affinity set. Thanks to
  Ole Bjørn Hessen. [GL #2245]
