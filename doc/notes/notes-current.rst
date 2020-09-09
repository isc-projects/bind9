.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.8
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

- New ``rndc`` command ``rndc dumpdb -expired`` that dumps the cache database
  to the dump-file including expired RRsets that are awaiting cleanup, for
  diagnostic purposes. [GL #1870]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Updating contents of an RPZ zone which contained names spelled using
  varying letter case could cause some processing rules in that RPZ zone
  to be erroneously ignored. [GL #2169]

- `named` would report invalid memory size when running in an environment
  that doesn't properly report number of available memory pages or pagesize.
  [GL #2166]
