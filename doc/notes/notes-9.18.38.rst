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

Notes for BIND 9.18.38
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix an issue when some specific queries could remain unanswered with
  serve-stale enabled.

  When :iscman:`named` was running with stale answers enabled and with
  the :any:`stale-answer-client-timeout` configuration option set to
  ``0``, in certain situations it was possible that some queries could
  remain unanswered.  This has been fixed. :gl:`#5383`

New Features
~~~~~~~~~~~~

- Add support for the CO flag to :iscman:`dig`.

  Add support for Compact Denial of Existence to :iscman:`dig`.  This
  includes showing the CO (Compact Answers OK) flag when displaying
  messages and adding an option to set the CO flag when making queries
  (:option:`dig +coflag`). :gl:`#5319`

Bug Fixes
~~~~~~~~~

- Correct the default :any:`interface-interval` from 60s to 60m.

  When the :any:`interface-interval` parser was changed from a
  ``uint32`` parser to a duration parser, the default value stayed at
  plain number ``60`` which now means 60 seconds instead of 60 minutes.
  The documentation also incorrectly states that the value is in
  minutes. That has been fixed. :gl:`#5246`

- Fix a :any:`purge-keys` bug when using multiple views of a zone.

  Previously, when a DNSSEC key was purged by one zone view, other zone
  views would return an error about missing key files. This has been
  fixed. :gl:`#5315`
