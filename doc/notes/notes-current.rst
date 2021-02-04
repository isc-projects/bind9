.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.10
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- A new option, ``stale-answer-client-timeout``, has been added to
  improve ``named``'s behavior with respect to serving stale data. The option
  defines the amount of time ``named`` waits before attempting
  to answer the query with a stale RRset from cache. If a stale answer
  is found, ``named`` continues the ongoing fetches, attempting to
  refresh the RRset in cache until the ``resolver-query-timeout`` interval is
  reached.

  The default value is ``1800`` (in milliseconds) and the maximum value is
  bounded to ``resolver-query-timeout`` minus one second. A value of
  ``0`` immediately returns a cached RRset if available, and still
  attempts a refresh of the data in cache.

  The option can be disabled by setting the value to ``off`` or
  ``disabled``. It also has no effect if ``stale-answer-enable`` is
  disabled. [GL #2247]

- Also return stale data if an error occurred and we are not resuming a
  query (and serve-stale is enabled). This may happen for example if
  ``fetches-per-server`` or ``fetches-per-zone` limits are reached. In this
  case, we will try to answer DNS requests with stale data, but not start
  the ``stale-refresh-time`` window. [GL #2434]

- ``named`` now supports XFR-over-TLS (XoT) for incoming as well as
  outgoing zone transfers.  Addresses in a ``primaries`` list can take
  an optional ``tls`` option which specifies either a previously configured
  ``tls`` statement or ``ephemeral``. [GL #2392]

- Support for DNS-over-HTTPS (DoH) was added to ``named``. Because of
  this, the ``nghttp2`` HTTP/2 library is now required for building the
  development branch of BIND 9. Both TLS-encrypted and unencrypted
  HTTP/2 connections are supported (the latter may be used to offload
  encryption to other software).

  Note that there is no client-side support for HTTPS as yet; this will be
  added to ``dig`` in a future release. [GL #1144]

Removed Features
~~~~~~~~~~~~~~~~

- A number of non-working configuration options that had been marked
  as obsolete in previous releases have now been removed completely.
  Using any of the following options is now considered a configuration
  failure:
  ``acache-cleaning-interval``, ``acache-enable``, ``additional-from-auth``,
  ``additional-from-cache``, ``allow-v6-synthesis``, ``cleaning-interval``,
  ``dnssec-enable``, ``dnssec-lookaside``, ``filter-aaaa``,
  ``filter-aaaa-on-v4``, ``filter-aaaa-on-v6``, ``geoip-use-ecs``, ``lwres``,
  ``max-acache-size``, ``nosit-udp-size``, ``queryport-pool-ports``,
  ``queryport-pool-updateinterval``, ``request-sit``, ``sit-secret``,
  ``support-ixfr``, ``use-queryport-pool``, ``use-ixfr``. [GL #1086]

Feature Changes
~~~~~~~~~~~~~~~

- The SONAMEs for BIND 9 libraries now include the current BIND 9
  version number, in an effort to tightly couple internal libraries with
  a specific release. This change makes the BIND 9 release process both
  simpler and more consistent while also unequivocally preventing BIND 9
  binaries from silently loading wrong versions of shared libraries (or
  multiple versions of the same shared library) at startup. [GL #2387]

- The default value of ``max-stale-ttl`` has been changed from 12 hours to 1
  day, and the default value of ``stale-answer-ttl`` has been changed from 1
  second to 30 seconds, following RFC 8767 recommendations. [GL #2248]

- When ``check-names`` is in effect, A records below an ``_spf``, ``_spf_rate``
  and ``_spf_verify`` labels (which are employed by the ``exists`` SPF
  mechanism defined inr:rfc:`7208` section 5.7/appendix D1) are no longer 
  reported as warnings/errors.  [GL #2377]

Bug Fixes
~~~~~~~~~

- KASP incorrectly set signature validity to the value of the DNSKEY signature
  validity. This is now fixed. [GL #2383]

- Previously, ``dnssec-keyfromlabel`` crashed when operating on an ECDSA key.
  This has been fixed. [GL #2178]

- The use of named ACLs in ``allow-update`` was broken in BIND 9.17.9 and
  BIND 9.16.11, preventing ``named`` from starting. [GL #2413]

- When migrating to ``dnssec-policy``, BIND considered keys with the "Inactive"
  and/or "Delete" timing metadata as possible active keys. This has been fixed.
  [GL #2406]

- Fixed the "three is a crowd" key rollover bug in ``dnssec-policy``. When keys
  rolled faster than the time required to finish the rollover procedure, the
  successor relation equation failed because it assumed only two keys were
  taking part in a rollover. This could lead to premature removal of
  predecessor keys. BIND 9 now implements a recursive successor relation, as
  described in the paper "Flexible and Robust Key Rollover" (Equation (2)).
  [GL #2375]

- If an invalid key name (e.g. "a..b") was specified in a ``primaries``
  list in ``named.conf``, the wrong size was passed to ``isc_mem_put()``,
  which resulted in the returned memory being put on the wrong freed
  list. This has been fixed. [GL #2460]

- If an outgoing packet would exceed max-udp-size, it would be dropped instead
  of sending a proper response back.  Rollback setting the IP_DONTFRAG on the
  UDP sockets that we enabled during the DNS Flag Day 2020 to fix this issue.
  [GL #2487]
