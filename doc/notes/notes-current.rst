.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.18
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

- None.

Bug Fixes
~~~~~~~~~

- Fixed a bug that caused the NSEC salt to be changed for KASP zones on
  every startup. :gl:`#2725`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`

- When preparing DNS responses, ``named`` could replace the letters
  ``W`` (uppercase) and ``w`` (lowercase) with ``\000``. This has been
  fixed. :gl:`#2779`

- The configuration-checking code failed to account for the inheritance
  rules of the ``key-directory`` option. As a side effect of this flaw,
  the code detecting ``key-directory`` conflicts for zones using KASP
  incorrectly reported unique key directories as being reused. This has
  been fixed. :gl:`#2778`

- A deadlock at startup was introduced when fixing :gl:`#1875` because when
  locking key files for reading and writing, "in-view" logic was not taken into
  account. This has been fixed. [GL #2783]
