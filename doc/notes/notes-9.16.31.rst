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

Notes for BIND 9.16.31
----------------------

Bug Fixes
~~~~~~~~~

- Fix the assertion failure caused by TCP connection closing between the
  connect (or accept) and the read from the socket. :gl:`#3400`

- ``named`` could crash during a very rare situation that could arise when
  validating a query which had timed out at that same exact moment. This has
  been fixed. :gl:`#3398`
