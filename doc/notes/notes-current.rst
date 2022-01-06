.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.22
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- ``named`` now logs TLS pre-master secrets for debugging purposes when
  the ``SSLKEYLOGFILE`` environment variable is set. This enables
  troubleshooting issues with encrypted DNS traffic. :gl:`#2723`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- If signatures created by the ZSK are expired, and the ZSK private key is offline,
  allow the expired signatures to be replaced with signatures created by the KSK.
  :gl:`#3049`

- On FreeBSD, a TCP connection would leak a small amount of heap memory leading
  to out-of-memory problem in a long run. This has been fixed. :gl:`#3051`

- Under certain circumstances, the signed version of an inline-signed
  zone could be dumped to disk without the serial number of the unsigned
  version of the zone, preventing resynchronization of zone contents
  after ``named`` restart in case the unsigned zone file gets modified
  while ``named`` is not running. This has been fixed. :gl:`#3071`

- Under certain circumstances, reading from the raw TCP channels used
  for rndc and statistics could cause assertion failure.  This has been
  fixed. :gl:`#3079`
