.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.12
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The GSSAPI no longer uses the ISC implementation of the SPNEGO
  mechanism and instead relies on the SPNEGO implementation from the
  system Kerberos library. All major Kerberos libraries contain the
  SPNEGO mechanism implementation. This change was implemented in BIND
  9.17.2, but it was not included in the release notes at the time.
  [GL #2607]

- The default value for the ``stale-answer-client-timeout`` option was
  changed from ``1800`` (ms) to ``off``. The default value may be
  changed again in future releases as this feature matures. [GL #2608]

- Implement ``draft-vandijk-dnsop-nsec-ttl``, NSEC(3) TTL values are now set to
  the minimum of the SOA MINIMUM value and the SOA TTL. [GL #2347].

Bug Fixes
~~~~~~~~~

- When calling ``rndc dnssec -rollover`` or ``rndc checkds -checkds``,
  ``named`` now updates the keys immediately, avoiding unnecessary rollover
  delays. [#2488]

- Dynamic zones with ``dnssec-policy`` that were frozen could not be thawed.
  This has been fixed. [GL #2523]

- CDS/CDNSKEY DELETE records are now removed when a zone transitioned from
  secure to insecure. "named-checkzone" no longer complains if such records
  exist in an unsigned zone. [GL #2517]

- Fix a crash when transferring a zone over TLS, after "named" previously
  skipped a master. [GL #2562]

- It was discovered that the TCP idle and initial timeouts were incorrectly
  applied in the BIND 9.16 and 9.17 branches. Only the ``tcp-initial-timeout``
  was applied on the whole connection, even if the connection were still active,
  which could cause a large zone transfer to be sent back to the client. The
  default setting for ``tcp-initial-timeout`` was 30 seconds, which meant that
  any TCP connection taking more than 30 seconds was abruptly terminated. This
  has been fixed. [GL #2573]

- When ``stale-answer-client-timeout`` was set to a positive value and
  recursion for a client query completed when ``named`` was about to look for
  a stale answer, an assertion could fail in ``query_respond()``, resulting in
  a crash. This has been fixed. [GL #2594]

- After upgrading to the previous release, journal files for trust anchor
  databases (e.g., ``managed-keys.bind.jnl``) could be left in a corrupt
  state. (Other zone journal files were not affected.) This has been
  fixed. If a corrupt journal file is detected, ``named`` can now recover
  from it. [GL #2600]

- When dumping the cache to file, TTLs were being increased with
  ``max-stale-ttl``. Also the comment above stale RRsets could have nonsensical
  values if the RRset was still marked a stale but the ``max-stale-ttl`` has
  passed (and is actually an RRset awaiting cleanup). Both issues have now
  been fixed. [GL #389] [GL #2289]

- ``named`` would overwrite a zone file unconditionally when it recovered from
  a corrupted journal. [GL #2623]
