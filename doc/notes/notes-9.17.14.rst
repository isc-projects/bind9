.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.14
----------------------

New Features
~~~~~~~~~~~~

- New configuration options, ``tcp-receive-buffer``,
  ``tcp-send-buffer``, ``udp-receive-buffer``, and ``udp-send-buffer``,
  have been added. These options allow the operator to fine-tune the
  receiving and sending buffers in the operating system. On busy
  servers, increasing the size of the receive buffers can prevent the
  server from dropping packets during short traffic spikes, and
  decreasing it can prevent the server from becoming clogged with
  queries that are too old and have already timed out. :gl:`#2313`

Feature Changes
~~~~~~~~~~~~~~~

- Zone dumping tasks are now run on separate asynchronous thread pools.
  This change prevents zone dumping from blocking network I/O.
  :gl:`#2732`

- The interface handling code has been refactored to use fewer
  resources, which should lead to less memory fragmentation and better
  startup performance. :gl:`#2433`

Bug Fixes
~~~~~~~~~

- The calculation of the estimated IXFR transaction size in
  ``dns_journal_iter_init()`` was invalid. This resulted in excessive
  AXFR-style IXFR responses. :gl:`#2685`

- Fixed an assertion failure that could occur if stale data was used to
  answer a query, and then a prefetch was triggered after the query was
  restarted (for example, to follow a CNAME). :gl:`#2733`

- If a query was answered with stale data on a server with DNS64
  enabled, an assertion could occur if a non-stale answer arrived
  afterward. This has been fixed. :gl:`#2731`

- Fixed an error which caused the ``IP_DONTFRAG`` socket option to be
  enabled instead of disabled, leading to errors when sending oversized
  UDP packets. :gl:`#2746`

- Zones which are configured in multiple views, with different values
  set for ``dnssec-policy`` and with identical values set for
  ``key-directory``, are now detected and treated as a configuration
  error. :gl:`#2463`

- A race condition could occur when reading and writing key files for
  zones using KASP and configured in multiple views. This has been
  fixed. :gl:`#1875`
