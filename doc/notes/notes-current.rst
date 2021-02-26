.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.11
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- ``dig`` has been extended to support DNS-over-HTTPS (DoH) queries,
  using ``dig +https`` and related options. [GL #1641]

- A new ``purge-keys`` option has been added to ``dnssec-policy``. It
  sets the period of time that key files are retained after becoming
  obsolete due to a key rollover; the default is 90 days. This feature
  can be disabled by setting ``purge-keys`` to 0. [GL #2408]

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- If an invalid key name (e.g. ``a..b``) was specified in a
  ``primaries`` list in ``named.conf``, the wrong size was passed to
  ``isc_mem_put()``, which resulted in the returned memory being put on
  the wrong free list and prevented ``named`` from starting up. This has
  been fixed. [GL #2460]

- If an outgoing packet exceeded ``max-udp-size``, ``named`` dropped it
  instead of sending back a proper response. To prevent this problem,
  the ``IP_DONTFRAG`` option is no longer set on UDP sockets, which has
  been happening since BIND 9.17.6. [GL #2466]

- NSEC3 records were not immediately created when signing a dynamic zone
  using ``dnssec-policy`` with ``nsec3param``. This has been fixed.
  [GL #2498]

- An invalid direction field (not one of ``N``, ``S``, ``E``, ``W``) in
  a LOC record resulted in an INSIST failure when a zone file containing
  such a record was loaded. [GL #2499]

- ``named`` crashed when it was allowed to serve stale answers and
  ``stale-answer-client-timeout`` was triggered without any (stale) data
  available in the cache to answer the query. [GL #2503]

- Zone journal (``.jnl``) files created by versions of ``named`` prior
  to 9.16.12 were no longer compatible; this could cause problems when
  upgrading if journal files were not synchronized first. This has been
  corrected: older journal files can now be read when starting up. When
  an old-style journal file is detected, it is updated to the new format
  immediately after loading.

  Note that journals created by the current version of ``named`` are not
  usable by versions prior to 9.16.12. Before downgrading to a prior
  release, users are advised to ensure that all dynamic zones have been
  synchronized using ``rndc sync -clean``.

  A journal file's format can be changed manually by running
  ``named-journalprint -d`` (downgrade) or ``named-journalprint -u``
  (upgrade). Note that this *must not* be done while ``named`` is
  running. [GL #2505]
