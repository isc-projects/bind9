.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.0
---------------------

Known Issues
~~~~~~~~~~~~

-  UDP network ports used for listening can no longer simultaneously be
   used for sending traffic. An example configuration which triggers
   this issue would be one which uses the same ``address:port`` pair for
   ``listen-on(-v6)`` statements as for ``notify-source(-v6)`` or
   ``transfer-source(-v6)``. While this issue affects all operating
   systems, it only triggers log messages (e.g. "unable to create
   dispatch for reserved port") on some of them. There are currently no
   plans to make such a combination of settings work again.

New Features
~~~~~~~~~~~~

-  When a secondary server receives a large incremental zone transfer
   (IXFR), it can have a negative impact on query performance while the
   incremental changes are applied to the zone. To address this,
   ``named`` can now limit the size of IXFR responses it sends in
   response to zone transfer requests. If an IXFR response would be
   larger than an AXFR of the entire zone, it will send an AXFR response
   instead.

   This behavior is controlled by the ``max-ixfr-ratio`` option - a
   percentage value representing the ratio of IXFR size to the size of a
   full zone transfer. The default is ``100%``. [GL #1515]

-  A new RPZ option ``nsdname-wait-recurse`` controls whether
   RPZ-NSDNAME rules should always be applied even if the names of
   authoritative name servers for the query name need to be looked up
   recurively first. The default is ``yes``. Setting it to ``no`` speeds
   up initial responses by skipping RPZ-NSDNAME rules when name server
   domain names are not yet in the cache. The names will be looked up in
   the background and the rule will be applied for subsequent queries.
   [GL #1138]

Feature Changes
~~~~~~~~~~~~~~~

-  The system-provided POSIX Threads read-write lock implementation is
   now used by default instead of the native BIND 9 implementation.
   Please be aware that glibc versions 2.26 through 2.29 had a bug_ that
   could cause BIND 9 to deadlock. A fix was released in glibc 2.30, and
   most current Linux distributions have patched or updated glibc, with
   the notable exception of Ubuntu 18.04 (Bionic) which is a work in
   progress. If you are running on an affected operating system, compile
   BIND 9 with ``--disable-pthread-rwlock`` until a fixed version of
   glibc is available. [GL !3125]

.. _bug: https://sourceware.org/bugzilla/show_bug.cgi?id=23844

-  The ``rndc nta -dump`` and ``rndc secroots`` commands now both
   include ``validate-except`` entries when listing negative trust
   anchors. These are indicated by the keyword ``permanent`` in place of
   the expiry date. [GL #1532]

Bug Fixes
~~~~~~~~~

-  Fixed re-signing issues with inline zones which resulted in records
   being re-signed late or not at all.
