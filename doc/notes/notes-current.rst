.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.25
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

- The default memory allocator has been switched from ``internal`` to
  ``external`` and new command line option ``-M internal`` has been added to
  ``named``. :gl:`#2398`

Bug Fixes
~~~~~~~~~

- On FreeBSD, a TCP connection would leak a small amount of heap memory leading
  to out-of-memory problem in a long run. This has been fixed. :gl:`#3051`

- Overall memory use by ``named`` was optimized and reduced.  :gl:`#2398`

- Under certain circumstances, the signed version of an inline-signed zone could
  be dumped to disk without the serial number of the unsigned version of the
  zone being saved. This could prevent resynchronization of zone contents after
  ``named`` restarted, if the unsigned zone file had been modified while
  ``named`` was not running. This has been fixed. :gl:`#3071`
