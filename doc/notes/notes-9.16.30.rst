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

Notes for BIND 9.16.30
----------------------

Bug Fixes
~~~~~~~~~

- Key files were updated every time the ``dnssec-policy`` key manager
  ran, whether the metadata had changed or not. :iscman:`named` now
  checks whether changes were applied before writing out the key files.
  :gl:`#3302`

- DNSSEC-signed catalog zones were not being processed correctly. This
  has been fixed. :gl:`#3380`
