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

- A malformed incoming IXFR transfer could trigger an assertion failure
  in ``named``, causing it to quit abnormally. (CVE-2021-25214)

  ISC would like to thank Greg Kuechle of SaskTel for bringing this
  vulnerability to our attention. [GL #2467]

- ``named`` crashed when a DNAME record placed in the ANSWER section
  during DNAME chasing turned out to be the final answer to a client
  query. (CVE-2021-25215)

  ISC would like to thank `Siva Kakarla`_ for bringing this
  vulnerability to our attention. [GL #2540]

.. _Siva Kakarla: https://github.com/sivakesava1

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

- The ISC implementation of SPNEGO was removed from BIND 9 source code.
  Instead, BIND 9 now always uses the SPNEGO implementation provided by
  the system GSSAPI library when it is built with GSSAPI support. All
  major contemporary Kerberos/GSSAPI libraries contain an implementation
  of the SPNEGO mechanism. This change was introduced in BIND 9.17.2,
  but it was not included in the release notes at the time. [GL #2607]

- The default value for the ``stale-answer-client-timeout`` option was
  changed from ``1800`` (ms) to ``off``. The default value may be
  changed again in future releases as this feature matures. [GL #2608]

Bug Fixes
~~~~~~~~~

- TCP idle and initial timeouts were being incorrectly applied: only the
  ``tcp-initial-timeout`` was applied on the whole connection, even if
  the connection were still active, which could prevent a large zone
  transfer from being sent back to the client. The default setting for
  ``tcp-initial-timeout`` was 30 seconds, which meant that any TCP
  connection taking more than 30 seconds was abruptly terminated. This
  has been fixed. [GL #2583]

- When ``stale-answer-client-timeout`` was set to a positive value and
  recursion for a client query completed when ``named`` was about to
  look for a stale answer, an assertion could fail in
  ``query_respond()``, resulting in a crash. This has been fixed.
  [GL #2594]

- After upgrading to the previous release, journal files for trust
  anchor databases (e.g. ``managed-keys.bind.jnl``) could be left in a
  corrupt state. (Other zone journal files were not affected.) This has
  been fixed. If a corrupt journal file is detected, ``named`` can now
  recover from it. [GL #2600]

- CDS/CDNSKEY DELETE records are now removed when a zone transitions
  from a secure to an insecure state. ``named-checkzone`` also no longer
  reports an error when such records are found in an unsigned zone.
  [GL #2517]

- Zones using KASP could not be thawed after they were frozen using
  ``rndc freeze``. This has been fixed. [GL #2523]

- After ``rndc checkds -checkds`` or ``rndc dnssec -rollover`` is used,
  ``named`` now immediately attempts to reconfigure zone keys. This
  change prevents unnecessary key rollover delays. [GL #2488]

- ``named`` crashed after skipping a primary server while transferring a
  zone over TLS. This has been fixed. [GL #2562]
