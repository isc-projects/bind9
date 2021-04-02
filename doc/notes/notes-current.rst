.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.14
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
  system Kerberos library. All major Kerberos libraries contain the SPNEGO
  mechanism implementation. [GL #2607]

Bug Fixes
~~~~~~~~~

- Previously, a memory leak could occur when ``named`` failed to bind a UDP
  socket to a network interface, caused by an interface shutdown routine that
  was missing in the error handling block. This has been fixed. [GL #2575]

- When calling ``rndc dnssec -rollover`` or ``rndc checkds -checkds``,
  ``named`` now updates the keys immediately, avoiding unnecessary rollover
  delays. [#2488]

- Dynamic zones with ``dnssec-policy`` that were frozen could not be thawed.
  This has been fixed. [GL #2523]

- CDS/CDNSKEY DELETE records are now removed when a zone transitioned from
  secure to insecure. "named-checkzone" no longer complains if such records
  exist in an unsigned zone. [GL #2517]

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
