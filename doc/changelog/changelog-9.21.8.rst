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

BIND 9.21.8
-----------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-40775] Prevent assertion when processing TSIG algorithm.
  ``1665e05438a``

  DNS messages that included a Transaction Signature (TSIG) containing
  an invalid value in the algorithm field caused :iscman:`named` to
  crash with an assertion failure. This has been fixed.
  :cve:`2025-40775` :gl:`#5300`

New Features
~~~~~~~~~~~~

- Implement tcp-primaries-timeout. ``2054186f408``

  The new `tcp-primaries-timeout` configuration option works the same
  way as the older `tcp-initial-timeout` option, but applies only to the
  TCP connections made to the primary servers, so that the timeout value
  can be set separately for them. By default, it's set to 150, which is
  15 seconds. :gl:`#3649` :gl:`!9376`

Feature Changes
~~~~~~~~~~~~~~~

- Use jinja2 templates in system tests. ``dfe755a5d6f``

  `python-jinja2` is now required to run system tests. :gl:`#4938`
  :gl:`!9588`

- Reduce QPDB_VIRTUAL to 10 seconds. ``ed8421f405a``

  The QPDB_VIRTUAL value was introduced to allow the clients (presumably
  ns_clients) that has been running for some time to access the cached
  data that was valid at the time of its inception.  The default value
  of 5 minutes is way longer than longevity of the ns_client object as
  the resolver will give up after 2 minutes.

  Reduce the value to 10 seconds to accomodate to honour the original
  more closely, but still allow some leeway for clients that started
  some time in the past.

  Our measurements show that even setting this value to 0 has no
  statistically significant effect, thus the value of 10 seconds should
  be on the safe side. :gl:`!10309`

Bug Fixes
~~~~~~~~~

- Fix EDNS yaml output. ``6285cc3476c``

  `dig` was producing invalid YAML when displaying some EDNS options.
  This has been corrected.

  Several other improvements have been made to the display of EDNS
  option data: - We now use the correct name for the UPDATE-LEASE
  option, which was previously displayed as "UL", and split it into
  separate LEASE and LEASE-KEY components in YAML mode. - Human-readable
  durations are now displayed as comments in YAML mode so as not to
  interfere with machine parsing. - KEY-TAG options are now displayed as
  an array of integers in YAML mode. - EDNS COOKIE options are displayed
  as separate CLIENT and SERVER components, and cookie STATUS is a
  retrievable variable in YAML mode. :gl:`#5014` :gl:`!9695`

- Return DNS COOKIE and NSID with BADVERS. ``79c50d45384``

  This change allows the client to identify the server that returns the
  BADVERS and to provide a DNS SERVER COOKIE to be included in the
  resend of the request. :gl:`#5235` :gl:`!10334`

- Disable own memory context for libxml2 on macOS. ``6f3fea837f0``

  Apple broke custom memory allocation functions in the system-wide
  libxml2 starting with macOS Sequoia 15.4.  Usage of the custom memory
  allocation functions has been disabled on macOS. :gl:`#5268`
  :gl:`!10374`

- `check_private` failed to account for the length byte before the OID.
  ``ecbae71fe9a``

  In PRIVATEOID keys, the key data begins with a length byte followed
  by an ASN.1 object identifier that indicates the cryptographic
  algorithm  to use. Previously, the length byte was not accounted for
  when  checking the contents of keys and signatures, which could have
  led to interoperability problems with any zones signed using
  PRIVATEOID. This has been fixed. :gl:`#5270` :gl:`!10372`

- Fix a serve-stale issue with a delegated zone. ``58a0e6cc614``

  When ``stale-answer-client-timeout 0`` option was enabled, it could be
  ignored when resolving a zone which is a delegation of an
  authoritative zone belonging to the resolver. This has been fixed.
  :gl:`#5275` :gl:`!10381`

- Move the call_rcu_thread explicit create and shutdown to isc_loop.
  ``e373f4062fe``

  When isc__thread_initialize() is called from a library constructor, it
  could be called before we fork the main process.  This happens with
  named, and then we have the call_rcu_thread attached to the pre-fork
  process and not the post-fork process, which means that the initial
  process will never shutdown, because there's noone to tell it so.

  Move the isc__thread_initialize() and isc__thread_shutdown() to the
  isc_loop unit where we call it before creating the extra thread and
  after joining all the extra threads respectively. :gl:`#5281`
  :gl:`!10394`

- Fix a date race in qpcache_addrdataset() ``47ccf613eb0``

  The 'qpnode->nsec' structure member isn't protected by a lock and
  there's a data race between the reading and writing parts in the
  qpcache_addrdataset() function. Use a node read lock for accessing
  'qpnode->nsec' in qpcache_addrdataset(). Add an additional
  'qpnode->nsec != DNS_DB_NSEC_HAS_NSEC' check under a write lock to be
  sure that no other competing thread changed it in the time when the
  read lock is unlocked and a write lock is not acquired yet.
  :gl:`#5285` :gl:`!10397`

- Fix the ksr two-tone test. ``405f8a7bd85``

  The two-tone ksr subtest (test_ksr_twotone) depended on the
  dnssec-policy keys algorithm values in named.conf being entered in
  numerical order.  As the algorithms used in the test can be selected
  randomly this does not always happen. Sort the dnssec-policy keys by
  algorithm when adding them to the key list from named.conf.
  :gl:`#5286` :gl:`!10395`

- Return the correct NSEC3 records for NXDOMAIN responses.
  ``1ec15358278``

  The wrong NSEC3 records were sometimes returned as proof that the
  QNAME did not exist. This has been fixed. :gl:`#5292` :gl:`!10447`

- Call rcu_barrier earlier in the destructor. ``962b75dca46``

  If a call_rcu thread is running, there is a possible race condition
  where the destructors run before all call_rcu callbacks have finished
  running. This can happen, for example, if the call_rcu callback tries
  to log something after the logging context has been torn down.

  In !10394, we tried to counter this by explicitely creating a call_rcu
  thread an shutting it down before running the destructors, but it is
  possible for things to "slip" and end up on the default call_rcu
  thread.

  As a quickfix, this commit moves an rcu_barrier() that was in the mem
  context destructor earlier, so that it "protects" all libisc
  destructors. :gl:`#5296` :gl:`!10423`

- Fix the error handling of put_yamlstr calls. ``fad97e3cd11``

  The return value was sometimes being ignored when it shouldn't have
  been. :gl:`#5301` :gl:`!10432`


