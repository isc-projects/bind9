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

BIND 9.18.37
------------

Bug Fixes
~~~~~~~~~

- Unify the int32_t vs int_fast32_t when working with atomic types.
  ``8665d3be39c``

  There's a mismatch between the atomic and non-atomic types that could
  potentialy lead to a rwlock deadlock (after two billion 2^32) writes.
  Use int_fast32_t when loading the atomic_int_fast32_t types in the
  isc_rwlock unit. :gl:`#5280` :gl:`!10390`


