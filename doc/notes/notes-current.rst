.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Notes for BIND 9.19.1
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

- The Object Identifier (OID) embedded at the start of a PRIVATEOID public
  key in a KEY, DNSKEY, CDNSKEY, or RKEY resource record is now checked to
  ensure that it is valid when reading from zone files or receiving data
  on the wire, and the OID is now printed when the ``dig +rrcomments``
  option is used. Similarly, the name embedded at the start of a PRIVATEDNS
  public key is also checked for validity. :gl:`#3234`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- CDS and CDNSKEY DELETE records are removed from the zone when configured with
  'auto-dnssec maintain;'. This has been fixed. :gl:`#2931`.
