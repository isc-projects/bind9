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

BIND 9.21.10
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-40777] Fix a possible assertion failure when using the
  'stale-answer-client-timeout 0' option. ``7fafa0e48f8``

  In specific circumstances the :iscman:`named` resolver process could
  terminate unexpectedly when stale answers were enabled and the
  ``stale-answer-client-timeout 0`` configuration option was used. This
  has been fixed. :gl:`#5372`

New Features
~~~~~~~~~~~~

- "Add code paths to fully support PRIVATEDNS and PRIVATEOID keys"
  ``119f511a458``

  Added support for PRIVATEDNS and PRIVATEOID key usage. Added
  PRIVATEOID test algorithms using the assigned OIDs for RSASHA256 and
  RSASHA512.

  Added code to support proposed DS digest types that encode the
  PRIVATEDNS and PRIVATEOID identifiers at the start of the digest field
  of the DS record. This code is disabled by default. :gl:`#3240`
  :gl:`!10341`

- Add "named-makejournal" tool. ``6ef16565b43``

  The `named-makejournal` tool reads two zone files for the same domain,
  compares them, and generates a journal file from the differences.
  :gl:`#5164` :gl:`!10081`

- Add support for the CO flag to dig. ``419ad060238``

  Add support to display the CO (Compact Answers OK flag)
  when displaying messages.

  Add support to set the CO flag when making queries in dig (+coflag).
  :gl:`#5319` :gl:`!10482`

- Replace the build system with meson. ``0c7a54095f6``

  This MR replaces the build system with meson.

  Speed: Meson is noticeably faster to setup and build than
  automake/autoconf. The improvements will likely add up in CI and
  development over time.

  Readability: Readability is a subjective criteria but meson is
  generally regarded as easier to read compared to CMake and
  automake/autoconf.

  Developer Ergonomics: Meson produces a compilation database, doesn't
  require libtool wrapping of executables/debuggers and offers JSON
  based build introspection.

  WrapDB and downloading dependencies is a non-issue for us since it
  requires writing wrap files explicitly and has been disabled by
  default via the `wrap_mode=nofallback` project option as a measure.
  :gl:`!8989`

Feature Changes
~~~~~~~~~~~~~~~

- Change QP and qpcache logging from DEBUG(1) to DEBUG(3)
  ``01a49e8e47a``

  Currently qp and qpcache logs are too verbose and enabled at a level
  too low compared to how often the logging is useful.

  This commit increases the logging level, while keeping it configurable
  via a define. :gl:`!10604`

- Change isc_tid to be isc_tid_t type (a signed integer type)
  ``97bb7eb4df0``

  Change the internal type used for isc_tid unit to isc_tid_t to hide
  the specific integer type being used for the 'tid'.  Internally, the
  isc_tid unit is now using signed integer type.  This allows us to have
  negatively indexed arrays that works both for threads with assigned
  tid and the threads with unassigned tid.  Additionally, limit the
  number of threads (loops) to 512 (compile time default). :gl:`!10656`

- Parse user configuration before exclusive mode. ``b49f83a3e6c``

  Previously, `named.conf` was parsed while the server was in exclusive
  (i.e., single-threaded) mode and unable to answer queries. This could
  cause an unnecessary delay in query processing when the file was
  large. We now delay entry into exclusive mode until after the
  configuration has been parsed, but before it is applied. :gl:`!10418`

- Use RCU for rad name. ``32e86ed6434``

  The RAD/agent domain is a functionality from RFC 9567 that provides a
  suffix for reporting error messages. On every query context reset, we
  need to check if a RAD is configured and, if so, copy it.

  Since we allow the RAD to be changed by reconfiguring the zone, this
  access is currently protected by a mutex, which causes contention.

  This commit replaces the mutex with RCU to reduce contention. The
  change results in a 3% performance improvement in the 1M delegation
  test. :gl:`!10616`

Bug Fixes
~~~~~~~~~

- Fix the default interface-interval from 60s to 60m. ``d45109732bc``

  When the interface-interval parser was changed from uint32 parser to
  duration parser, the default value stayed at plain number `60` which
  now means 60 seconds instead of 60 minutes.  The documentation also
  incorrectly states that the value is in minutes.  That has been fixed.
  :gl:`#5246` :gl:`!10281`

- Fix purge-keys bug when using views. ``29c69d26d9f``

  Previously, when a DNSSEC key was purged by one zone view, other zone
  views would return an error about missing key files. This has been
  fixed. :gl:`#5315` :gl:`!10550`

- Use IPv6 queries in delv +ns. ``a37afc3bb18``

  `delv +ns` invokes the same code to perform name resolution as
  `named`, but it neglected to set up an IPv6 dispatch object first.
  Consequently, it was behaving more like `named -4`. It now sets up
  dispatch objects for both address families, and performs resolver
  queries to both v4 and v6 addresses, except when one of the address
  families has been suppressed by using `delv -4` or `delv -6`.
  :gl:`#5352` :gl:`!10563`

- Prevent false sharing for the .inuse member of isc_mem_t.
  ``38cc19d756a``

  Change the .inuse member of memory context to have a loop-local
  variable, so there's no contention even when the same memory context
  is shared among multiple threads. :gl:`#5354` :gl:`!10555`

- Add rdata type header files to dns_header_depfiles macro.
  ``29eaae06e48``

  The header file dns/rdatastruct.h was not being rebuilt when the rdata
  type header files where modified.      Removed proforma.c from the
  list.  It is a starting point for new types. :gl:`#5368` :gl:`!10574`

- Clean up CFG_ZONE_DELEGATION. ``b1a8938d1aa``

  `type delegation-only` has been obsolete for some time (see #3953) but
  the zone type flag for it was still defined in libisccfg. It has now
  been removed. :gl:`!10558`

- Fix RTD builds and minor documentation issues. ``181ad273e8c``

  Fix some leftover artifacts and information while transitioning BIND
  to Meson. Add CI job to verify that pre-generated config grammar files
  are up-to-date with code. :gl:`!10584`

- Remove zone keyopts field. ``9e345283934``

  The "keyopts" field of the dns_zone object was added to support
  "auto-dnssec"; at that time the "options" field already had most of
  its 32 bits in use by other flags, so it made sense to add a new
  field.

  Since then, "options" has been widened to 64 bits, and "auto-dnssec"
  has been obsoleted and removed. Most of the DNS_ZONEKEY flags are no
  longer needed. The one that still seems useful (_FULLSIGN) has been
  moved into DNS_ZONEOPT and the rest have been removed, along with
  "keyopts" and its setter/getter functions. :gl:`!10564`

- Various cleanups related to the isc_mem unit. ``f9528b88aea``

  :gl:`!10671`


