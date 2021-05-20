.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.17
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

- After the network manager was introduced to ``named`` to handle
  incoming traffic, it was discovered that recursive performance had
  degraded compared to previous BIND 9 versions. This has now been
  fixed by processing internal tasks inside network manager worker
  threads, preventing resource contention among two sets of threads.
  :gl:`#2638`

Bug Fixes
~~~~~~~~~

- Fix a race condition in reading and writing key files for KASP zones in
  multiple views. :gl:`#1875`

- Check ``key-directory`` conflicts in ``named.conf`` for zones in multiple
  views with different ``dnssec-policy``. Using the same ``key-directory`` for
  such zones is not allowed. :gl:`#2463`
