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

Notes for BIND 9.18.4
---------------------

Feature Changes
~~~~~~~~~~~~~~~

- Some more ``dnssec-policy`` configuration checks have been added to
  detect weird policies such as missing KSK and/or ZSK, and too short
  key lifetimes and re-sign periods. :gl:`#1611`.

Bug Fixes
~~~~~~~~~

- Key files were updated every time the ``dnssec-policy`` key manager ran,
  whether the metadata has changed or not. BIND now checks if changes were
  applied before writing out the key files. :gl:`#3302`.

- DNSSEC-signed catalog zones were not being processed correctly. This
  has been fixed. :gl:`#3380`.
