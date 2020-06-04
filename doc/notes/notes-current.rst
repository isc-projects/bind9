.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. _relnotes-9.16.4:

Notes for BIND 9.16.4
=====================

.. _relnotes-9.16.4-security:

Security Fixes
--------------

-  None.

.. _relnotes-9.16.4-known:

Known Issues
------------

-  None

.. _relnotes-9.16.4-changes:

Feature Changes
---------------

-  ``dig`` and other tools can now print the Extended DNS Error (EDE)
   option when it appears in a request or response. [GL #1834]

.. _relnotes-9.16.4-bugs:

-  The default value of ``max-stale-ttl`` has changed from 1 week to 12 hours.
   This option controls how long named retains expired RRsets in cache as a
   potential mitigation mechanism, should there be a problem with one or more
   domains.  Note that cache content retention is independent of whether or not
   stale answers will be used in response to client queries
   (``stale-answer-enable yes|no`` and ``rndc serve-stale on|off``).  Serving of
   stale answers when the authoritative servers are not responding must be
   explicitly enabled, whereas the retention of expired cache content takes
   place automatically on all versions of BIND that have this feature available.
   [GL #1877]

   .. warning:
       This change may be significant for administrators who expect that stale
       cache content will be automatically retained for up to 1 week.  Add
       option ``max-stale-ttl 1w;`` to named.conf to keep the previous behavior
       of named.

Bug Fixes
---------

-  ``named`` could crash with an assertion failure if the name of a
   database node was looked up while the database was being modified.
   [GL #1857]
-  Missing mutex and conditional destruction in netmgr code leads to a memory
   leak on BSD systems. [GL #1893].
-  Fix a bug in dnssec-policy keymgr where the check if a key has a
   successor would return a false positive if any other key in the
   keyring has a successor. [GL #1845]

-  With dnssec-policy, when creating a successor key, the goal state of
   the current active key (the predecessor) was not changed and thus was
   never is removed from the zone. [GL #1846]
