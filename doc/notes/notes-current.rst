.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.5
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- New ``rndc`` command ``rndc dnssec -checkds`` to tell ``named``
  that a DS record for a given zone or key has been published or withdrawn
  from the parent. Replaces the time-based ``parent-registration-delay``
  configuration option. [GL #1613]

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- In rare circumstances, named would exit with assertion failure when the number
  of nodes stored in the red-black-tree exceeds the maximum allowed size of the
  internal hashtable.  [GL #2104]
