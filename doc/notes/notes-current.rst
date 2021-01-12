.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.12
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

- The SONAMEs for BIND 9 libraries now include the current BIND 9
  version number, in an effort to tightly couple internal libraries with
  a specific release. This change makes the BIND 9 release process both
  simpler and more consistent while also unequivocally preventing BIND 9
  binaries from silently loading wrong versions of shared libraries (or
  multiple versions of the same shared library) at startup. [GL #2387]

- The default value of ``max-stale-ttl`` has been changed from 12 hours to 1
  day and the default value of ``stale-answer-ttl`` has been changed from 1
  second to 30 seconds, following RFC 8767 recommendations. [GL #2248]

- As part of an ongoing effort to use RFC 8499 terminology,
  ``primaries`` can now be used as a synonym for ``masters`` in
  ``named.conf``. Similarly, ``notify primary-only`` can now be used as
  a synonym for ``notify master-only``. The output of ``rndc
  zonestatus`` now uses ``primary`` and ``secondary`` terminology.
  [GL #1948]

Bug Fixes
~~~~~~~~~

- KASP incorrectly set signature validity to the value of the DNSKEY signature
  validity. This is now fixed. [GL #2383]
