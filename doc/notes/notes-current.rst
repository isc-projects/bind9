.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.14
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- New configuration options, ``tcp-receive-buffer``, ``tcp-send-buffer``,
  ``udp-receive-buffer``, and ``udp-send-buffer``, have been added.  These
  options allows the operator to fine tune the receiving and sending
  buffers in the operating system.  On busy servers, increasing the value
  of the receive buffers can prevent the server from dropping the packets
  during short spikes, and decreasing the value would prevent the server to
  became clogged up with queries that are too old and have already timeouted
  on the receiving side. :gl:`#2313`

- Run zone dumping tasks on separate asynchronous thread pools.  This change
  makes zone dumping no longer block networking I/O. :gl:`#2732`

Removed Features
~~~~~~~~~~~~~~~~

- Support for compiling and running BIND 9 natively on Windows has been
  completely removed.  The last release branch that has working Windows
  support is BIND 9.16. :gl:`#2690`

Feature Changes
~~~~~~~~~~~~~~~

- The interface handling code has been refactored to use fewer resources,
  which should lead to less memory fragmentation and better startup
  performance.  :gl:`#2433`

Bug Fixes
~~~~~~~~~

- Fix a race condition in reading and writing key files for KASP zones in
  multiple views. :gl:`#1875`

- Check ``key-directory`` conflicts in ``named.conf`` for zones in multiple
  views with different ``dnssec-policy``. Using the same ``key-directory`` for
  such zones is not allowed. :gl:`#2463`

- ``named-checkconf`` now complains if zones with ``dnssec-policy`` reference
  the same zone file more than once. :gl:`#2603`

- The calculation of the estimated IXFR transaction size by
  `dns_journal_iter_init()` was invalid.  This resulted in excessive
  AXFR-style-IXFR responses. :gl:`#2685`

- If a query was answered with stale data on a server with DNS64 enabled,
  an assertion could occur if a non-stale answer arrived afterward. This
  has been fixed. :gl:`#2731`

- Fixed an assertion failure that could occur if stale data was used
  to answer a query, and then a prefetch was triggered after the query
  was restarted (for example, to follow a CNAME). :gl:`#2733`

- Fix an error that would enable don't fragment socket option instead
  of disabling it leading to errors when sending the oversized UDP
  packets. [GL #2746]

- Fixed a bug that caused the NSEC salt to be changed for KASP zones on
  every startup. :gl:`#2725`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`
