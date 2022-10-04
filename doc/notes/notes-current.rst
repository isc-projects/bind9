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

Notes for BIND 9.16.34
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- :iscman:`named` now logs the supported cryptographic algorithms during
  startup and in the output of :option:`named -V`. :gl:`#3541`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

- Add support for parsing and validating ``dohpath`` to SVBC records.
  :gl:`#3544`

Bug Fixes
~~~~~~~~~

- Changing just the TSIG key names for primaries in catalog zones' member
  zones was not effective. :gl:`#3557`
