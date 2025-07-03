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

Notes for BIND 9.21.10
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-40777] Fix a possible assertion failure when using the
  'stale-answer-client-timeout 0' option.

  In specific circumstances the :iscman:`named` resolver process could
  terminate unexpectedly when stale answers were enabled and the
  ``stale-answer-client-timeout 0`` configuration option was used. This
  has been fixed. :gl:`#5372`

New Features
~~~~~~~~~~~~

- "Add code paths to fully support PRIVATEDNS and PRIVATEOID keys"

  Added support for PRIVATEDNS and PRIVATEOID key usage. Added
  PRIVATEOID test algorithms using the assigned OIDs for RSASHA256 and
  RSASHA512.

  Added code to support proposed DS digest types that encode the
  PRIVATEDNS and PRIVATEOID identifiers at the start of the digest field
  of the DS record. This code is disabled by default. :gl:`#3240`

- Add "named-makejournal" tool.

  The `named-makejournal` tool reads two zone files for the same domain,
  compares them, and generates a journal file from the differences.
  :gl:`#5164`

- Add support to set and display the CO flag.

  Add support to display the CO (Compact denial of existence Ok flag)
  when displaying messages.

  Add support to set the CO flag when making queries in dig (+coflag).
  :gl:`#5319`

Bug Fixes
~~~~~~~~~

- Fix the default interface-interval from 60s to 60m.

  When the interface-interval parser was changed from uint32 parser to
  duration parser, the default value stayed at plain number `60` which
  now means 60 seconds instead of 60 minutes.  The documentation also
  incorrectly states that the value is in minutes.  That has been fixed.
  :gl:`#5246`

- Fix purge-keys bug when using views.

  Previously, when a DNSSEC key was purged by one zone view, other zone
  views would return an error about missing key files. This has been
  fixed. :gl:`#5315`

- Use IPv6 queries in delv +ns.

  `delv +ns` invokes the same code to perform name resolution as
  `named`, but it neglected to set up an IPv6 dispatch object first.
  Consequently, it was behaving more like `named -4`. It now sets up
  dispatch objects for both address families, and performs resolver
  queries to both v4 and v6 addresses, except when one of the address
  families has been suppressed by using `delv -4` or `delv -6`.
  :gl:`#5352`


