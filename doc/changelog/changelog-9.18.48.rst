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

BIND 9.18.48
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix crash when reconfiguring zone update policy during active updates.
  ``2eaf84497ac``

  Fixed a crash that could occur when running rndc reconfig to change a
  zone's update policy (e.g., from allow-update to update-policy) while
  DNS UPDATE requests were being processed for that zone.

  ISC would like to thank Vitaly Simonovich for bringing this issue to
  our attention. :gl:`#5817` :gl:`!11739`

New Features
~~~~~~~~~~~~

- Add MOVE_OWNERSHIP() macro for transferring pointer ownership.
  ``d783ac4a476``

  A helper macro that returns the current value of a pointer and sets it
  to NULL in one expression, useful for transferring ownership in
  designated initializers. :gl:`!11737`

Feature Changes
~~~~~~~~~~~~~~~

- Exclude named.args.j2 and system test README files from license header
  checks. ``ce0d28d19cd``

  Exclude named.args.j2 files from license header checks so named.args
  can be generated from Jinja templates. Also exclude system test README
  files from the license header checks. :gl:`!11697`

- Use underscore for system test names. ``2dd5b2b90e9``

  Change the convention for system test directory names to always use an
  underscore rather than a hyphen. Names using underscore are valid
  python package names and can be used with standard `import` facilities
  in python, which allows easier code reuse. :gl:`!11712`

Bug Fixes
~~~~~~~~~

- Clear errno correctly. ``3f7f8293069``

  Zero errno before calling strtol. :gl:`#5773` :gl:`!11704`

- Fix a crash triggered by rndc modzone on zone from configuration file.
  ``0ac37a399a7``

  Calling `rndc modzone` on a zone that was configured in the
  configuration file caused a crash. This has been fixed.

  ISC would like to thank Nathan Reilly for reporting this. :gl:`#5800`
  :gl:`!11699`

- Fix OpenSSL 4 compatibility issue when calling X509_get_subject_name()
  ``cd11dd6cf34``

  Starting from OpenSSL 4 the the X509_get_subject_name() function
  returns a 'const' pointer to a name instead of a regular pointer.
  Duplicate the name before operating on it, then free it. :gl:`#5807`
  :gl:`!11693`

- Fix a crash triggered by rndc modzone on zone that already existed in
  NZF file. ``a0bfbe9a765``

  Calling `rndc modzone` didn't work properly for a zone hat was
  configured in  the configuration file. It could crash if BIND 9 was
  built without LMDB or if  there was already an NZF file for the zone.
  In addition, `rndc modzone` failed in subsequent attempts. These
  problems are now fixed. :gl:`#5826` :gl:`!11746`

- Fix data race on fctx->vresult in validated() ``5b7c54ae01d``

  Move the write to fctx->vresult after LOCK(&fctx->lock).  The field
  was being set before acquiring the lock, but dns_resolver_logfetch()
  reads it under the same lock from another thread. :gl:`!11722`


