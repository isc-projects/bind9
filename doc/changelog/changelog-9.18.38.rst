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

BIND 9.18.38
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix an issue when some specific queries could remain unanswered with
  serve-stale enabled. ``8ca561f6dce``

  When :iscman:`named` was running with stale answers enabled and with
  the ``stale-answer-client-timeout 0`` configuration option, in certain
  situations it was possible that some queries could remain unanswered.
  This has been fixed. :gl:`#5383`

New Features
~~~~~~~~~~~~

- Add support for the CO flag to dig. ``9e897623701``

  Add support to display the CO (Compact Answers OK flag)
  when displaying messages.

  Add support to set the CO flag when making queries in dig (+coflag).
  :gl:`#5319` :gl:`!10579`

Bug Fixes
~~~~~~~~~

- Fix the default interface-interval from 60s to 60m. ``0be568f921d``

  When the interface-interval parser was changed from uint32 parser to
  duration parser, the default value stayed at plain number `60` which
  now means 60 seconds instead of 60 minutes.  The documentation also
  incorrectly states that the value is in minutes.  That has been fixed.
  :gl:`#5246` :gl:`!10680`

- Fix purge-keys bug when using views. ``df417186ef2``

  Previously, when a DNSSEC key was purged by one zone view, other zone
  views would return an error about missing key files. This has been
  fixed. :gl:`#5315` :gl:`!10599`

- Set name for all the isc_mem contexts. ``6c216c18d01``

  :gl:`!10499`


