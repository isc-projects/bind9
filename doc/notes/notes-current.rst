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

Notes for BIND 9.17.23
----------------------

Security Fixes
~~~~~~~~~~~~~~

- The rules for acceptance of records into the cache have been tightened
  to prevent the possibility of poisoning if forwarders send records
  outside the configured bailiwick. (CVE-2021-25220)

  ISC would like to thank Xiang Li, Baojun Liu, and Chaoyi Lu from
  Network and Information Security Lab, Tsinghua University, and
  Changgen Zou from Qi An Xin Group Corp. for bringing this
  vulnerability to our attention. :gl:`#2950`

- TCP connections with ``keep-response-order`` enabled could leave the
  TCP sockets in the ``CLOSE_WAIT`` state when the client did not
  properly shut down the connection. (CVE-2022-0396) :gl:`#3112`

- Lookups involving a DNAME could trigger an assertion failure when
  ``synth-from-dnssec`` was enabled (which is the default).
  (CVE-2022-0635)

  ISC would like to thank Vincent Levigneron from AFNIC for bringing
  this vulnerability to our attention. :gl:`#3158`

- When chasing DS records, a timed-out or artificially delayed fetch
  could cause ``named`` to crash while resuming a DS lookup.
  (CVE-2022-0667) :gl:`#3129`

Known Issues
~~~~~~~~~~~~

- According to RFC 8310, Section 8.1, the Subject field MUST NOT be
  inspected when verifying a remote certificate while establishing a
  DNS-over-TLS connection. Only SubjectAltName must be checked
  instead. Unfortunately, some quite old versions of cryptographic
  libraries might lack the functionality to ignore the Subject
  field. It should have minimal production use consequences, as most
  of the production-ready certificates issued by certificate
  authorities will have SubjectAltNames set. In such a case, the
  Subject field is ignored. Only old platforms are affected by this,
  e.g., those supplied with OpenSSL versions older than 1.1.1.

New Features
~~~~~~~~~~~~

- :iscman:`dnssec-verify` and :iscman:`dnssec-signzone` now accept a ``-J`` option to
  specify a journal file to read when loading the zone to be verified or
  signed. :gl:`#2486`

- Add support for remote TLS certificates verification, both to BIND
  and ``dig``, making it possible to implement Strict and Mutual TLS
  authentication, as described in RFC 9103, Section 9.3. :gl:`#3163`

- Run RPZ updates on the specialized "offload" threads to reduce the amount
  of time they block query processing on the main networking threads.  This
  should increase the responsiveness of ``named`` when RPZ updates are being
  applied after an RPZ zone has been successfully transfered.  :gl:`#3190`

Removed Features
~~~~~~~~~~~~~~~~

- The IPv6 sockets are now explicitly restricted to sending and receiving IPv6
  packets only.  This renders the :iscman:`dig` option ``+mapped`` non-functioning and
  thus the option has been removed. :gl:`#3093`

- The ``keep-order-response`` option has been declared obsolete and the
  functionality has been removed.  :iscman:`named` expects DNS clients to be
  fully compliant with :rfc:`7766`. :gl:`#3140`

Feature Changes
~~~~~~~~~~~~~~~

- The DLZ API has been updated: EDNS Client-Subnet (ECS) options sent
  by a client are now included in the client information sent to DLZ
  modules when processing queries. :gl:`#3082`

- Add DEBUG(1) level messages when starting and ending BIND 9 task exclusive mode
  that stops the normal DNS operation (f.e. for reconfiguration, interface
  scans, and other events that require exclusive access to a shared resources).
  :gl:`#3137`

- The limit on the number of simultaneously processed pipelined DNS queries
  received over TCP has been dropped. Previously, it was capped at 23
  queries processed at the same time. :gl:`#3141`

- Add a new configuration option ``reuseport`` to disable
  load balancing on sockets in scenarios in which processing of
  Response Policy Zones (RPZ), Catalog Zones, or large zone transfers
  can cause service disruptions. See the BIND 9 ARM for more detail.
  :gl:`#3249`

Bug Fixes
~~~~~~~~~

- With libuv >= 1.37.0, the recvmmsg support would not be enabled in :iscman:`named`
  reducing the maximum query-response performance.  The recvmmsg support would
  be used only in libuv 1.35.0 and 1.36.0.  This has been fixed.  :gl:`#3095`

- A failed view configuration during a named reconfiguration procedure could
  cause inconsistencies in BIND internal structures, causing a crash or other
  unexpected errors.  This has been fixed.  :gl:`#3060`

- Restore logging "quota reached" message when accepting connection is over
  hard quota.  :gl:`#3125`

- Build errors were introduced in some DLZ modules due to an incomplete
  change in the previous release. This has been fixed. :gl:`#3111`

- An error in the processing of the ``blackhole`` ACL could cause some DNS
  requests sent by :iscman:`named` to fail - for example, zone transfer requests
  and SOA refresh queries - if the destination address or prefix was
  specifically excluded from the ACL using ``!``, or if the ACL was set
  to ``none``.  ``blackhole`` worked correctly when it was left unset, or
  if only positive-match elements were included. This has now been fixed.
  :gl:`#3157`

- TCP connections could hang indefinitely if the TCP write buffers
  were full because of the other party not reading sent data.  This has
  been fixed by adding a "write" timer. Connections that are hung
  while writing will now time out after the ``tcp-idle-timeout`` period
  has elapsed. :gl:`#3132`

- Client TCP connections are now closed immediately when data received
  cannot be parsed as a valid DNS request. :gl:`#3149`

- The ``max-transfer-time-out`` and ``max-transfer-idle-out`` options were
  not implemented when the BIND 9 networking stack was refactored in 9.16.
  The missing functionality has been re-implemented and outgoing zone
  transfers now time out properly when not progressing. :gl:`#1897`

- The statistics counter representing the current number of clients
  awaiting recursive resolution results (``RecursClients``) could be
  miscalculated in certain resolution scenarios, potentially causing the
  value of the counter to drop below zero. This has been fixed.
  :gl:`#3147`

- Invalid dnssec-policy definitions were being accepted where the
  defined keys did not cover both KSK and ZSK roles for a given
  algorithm.  This is now checked for and the dnssec-policy is
  rejected if both roles are not present for all algorithms in use.
  :gl:`#3142`

- Handling of the TCP write timeouts has been improved to track timeout
  for each TCP write separately leading to faster connection tear down
  in case the other party is not reading the data. :gl:`#3200`

- Zone maintenance DNS queries would retry forever while the
  destination server was unreachable. These queries include outgoing
  NOTIFY messages, refresh SOA queries, parental DS checks, and stub
  zone NS queries. For example, if a zone has any nameservers with
  IPv6 addresses and a secondary server without IPv6 connectivity, the
  IPv4-only server would keep trying to send a growing amount of
  NOTIFY traffic over IPv6. This futile traffic was not logged.
  :gl:`#3242`
