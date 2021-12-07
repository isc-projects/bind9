.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.24
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

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Previously, when an incoming TCP connection could not be accepted
  because the client closed the connection early, an error message of
  ``TCP connection failed: socket is not connected`` was logged. This
  message has been changed to ``Accepting TCP connection failed: socket
  is not connected``. The severity level at which this type of message
  is logged has also been changed from ``error`` to ``info`` for the
  following triggering events: ``socket is not connected``, ``quota
  reached``, and ``soft quota reached``. :gl:`#2700`

- ``dnssec-dsfromkey`` no longer generates DS records from revoked keys.
  :gl:`#853`

- The default memory allocator has been switched from ``internal`` to
  ``external`` and new command line option ``-M internal`` has been added to
  ``named``. :gl:`#2398`

Bug Fixes
~~~~~~~~~

- Removing a configured ``catalog-zone`` clause from the configuration,
  running ``rndc reconfig``, then bringing back the removed
  ``catalog-zone`` clause and running ``rndc reconfig`` again caused
  ``named`` to crash. This has been fixed. :gl:`#1608`

- On FreeBSD, a TCP connection would leak a small amount of heap memory leading
  to out-of-memory problem in a long run. This has been fixed. :gl:`#3051`

- Overall memory use by ``named`` was optimized and reduced.  :gl:`#2398`
