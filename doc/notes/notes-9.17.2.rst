.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.2
---------------------

Security Fixes
~~~~~~~~~~~~~~

-  To prevent exhaustion of server resources by a maliciously configured
   domain, the number of recursive queries that can be triggered by a
   request before aborting recursion has been further limited. Root and
   top-level domain servers are no longer exempt from the
   ``max-recursion-queries`` limit. Fetches for missing name server
   address records are limited to 4 for any domain. This issue was
   disclosed in CVE-2020-8616. :gl:`#1388`

-  Replaying a TSIG BADTIME response as a request could trigger an
   assertion failure. This was disclosed in CVE-2020-8617. :gl:`#1703`

-  It was possible to trigger an assertion when attempting to fill an
   oversized TCP buffer. This was disclosed in CVE-2020-8618.
   :gl:`#1850`

-  It was possible to trigger an INSIST failure when a zone with an
   interior wildcard label was queried in a certain pattern. This was
   disclosed in CVE-2020-8619. :gl:`#1111` :gl:`#1718`

Known Issues
~~~~~~~~~~~~

-  In this release, the build system has been significantly changed (see
   below) and there are several unresolved issues to be aware of when
   using a development release. Please refer to :gl:`GitLab issue #4
   <#4>` for a list of not-yet-resolved issues that will be fixed in
   future releases. :gl:`#4`

-  BIND crashes on startup when linked against libuv 1.36. This issue
   is related to ``recvmmsg()`` support in libuv, which was first
   included in libuv 1.35. The problem was addressed in libuv 1.37, but
   the relevant libuv code change requires a special flag to be set
   during library initialization in order for ``recvmmsg()`` support to
   be enabled. This BIND release sets that special flag when required,
   so ``recvmmsg()`` support is now enabled when BIND is compiled
   against either libuv 1.35 or libuv 1.37+; libuv 1.36 is still not
   usable with BIND. :gl:`#1761` :gl:`#1797`

New Features
~~~~~~~~~~~~

-  The BIND 9 build system has been changed to use a typical
   autoconf+automake+libtool stack. This should not make any difference
   for people building BIND 9 from release tarballs, but when building
   BIND 9 from the Git repository, ``autoreconf -fi`` needs to be run
   first. Extra attention is also needed when using non-standard
   ``./configure`` options. :gl:`#4`

-  Documentation was converted from DocBook to reStructuredText. The
   BIND 9 ARM is now generated using Sphinx and published on `Read the
   Docs`_. Release notes are no longer available as a separate document
   accompanying a release. :gl:`#83`

-  ``named`` and ``named-checkzone`` now reject master zones that have a
   DS RRset at the zone apex. Attempts to add DS records at the zone
   apex via UPDATE will be logged but otherwise ignored. DS records
   belong in the parent zone, not at the zone apex. :gl:`#1798`

-  Per-type record count limits can now be specified in
   ``update-policy`` statements, to limit the number of records of a
   particular type that can be added to a domain name via dynamic
   update. :gl:`#1657`

-  ``dig`` and other tools can now print the Extended DNS Error (EDE)
   option when it appears in a request or a response. :gl:`#1835`

-  ``dig +qid=<num>`` allows the user to specify a particular query ID
   for testing purposes. :gl:`#1851`

-  A new logging category, ``rpz-passthru``, was added, which allows RPZ
   passthru actions to be logged into a separate channel. :gl:`#54`

-  Zone timers are now exported via statistics channel. For primary
   zones, only the load time is exported. For secondary zones, exported
   timers also include expire and refresh times. Contributed by Paul
   Frieden, Verizon Media. :gl:`#1232`

Feature Changes
~~~~~~~~~~~~~~~

-  The default value of ``max-stale-ttl`` has changed from 1 week to 12
   hours. This option controls how long ``named`` retains expired RRsets
   in cache as a potential mitigation mechanism, should there be a
   problem with one or more domains. Note that cache content retention
   is independent of whether stale answers are used in response to
   client queries (``stale-answer-enable yes|no`` and ``rndc serve-stale
   on|off``). Serving of stale answers when the authoritative servers
   are not responding must be explicitly enabled, whereas the retention
   of expired cache content takes place automatically on all versions of
   BIND 9 that have this feature available. :gl:`#1877`

   .. warning::
       This change may be significant for administrators who expect that
       stale cache content will be automatically retained for up to 1
       week. Add option ``max-stale-ttl 1w;`` to ``named.conf`` to keep
       the previous behavior of ``named``.

-  BIND 9 no longer sets receive/send buffer sizes for UDP sockets,
   relying on system defaults instead. :gl:`#1713`

-  The default rwlock implementation has been changed back to the native
   BIND 9 rwlock implementation. :gl:`#1753`

-  BIND 9 binaries which are neither daemons nor administrative programs
   were moved to ``$bindir``. Only ``ddns-confgen``, ``named``,
   ``rndc``, ``rndc-confgen``, and ``tsig-confgen`` were left in
   ``$sbindir``. :gl:`#1724`

-  ``listen-on-v6 { any; }`` creates a separate socket for each
   interface. Previously, just one socket was created on systems
   conforming to :rfc:`3493` and :rfc:`3542`. This change was introduced
   in BIND 9.16.0, but it was accidentally omitted from documentation.
   :gl:`#1782`

-  The native PKCS#11 EdDSA implementation has been updated to PKCS#11
   v3.0 and thus made operational again. Contributed by Aaron Thompson.
   :gl:`!3326`

-  The OpenSSL ECDSA implementation has been updated to support PKCS#11
   via OpenSSL engine (see engine_pkcs11 from libp11 project).
   :gl:`#1534`

-  The OpenSSL EdDSA implementation has been updated to support PKCS#11
   via OpenSSL engine. Please note that an EdDSA-capable OpenSSL engine
   is required and thus this code is only a proof-of-concept for the
   time being. Contributed by Aaron Thompson. :gl:`#1763`

-  Message IDs in inbound AXFR transfers are now checked for
   consistency. Log messages are emitted for streams with inconsistent
   message IDs. :gl:`#1674`

-  The question section is now checked when processing AXFR, IXFR,
   and SOA replies while transferring a zone in. :gl:`#1683`

Bug Fixes
~~~~~~~~~

-  When fully updating the NSEC3 chain for a large zone via IXFR, a
   temporary loss of performance could be experienced on the secondary
   server when answering queries for nonexistent data that required
   DNSSEC proof of non-existence (in other words, queries that required
   the server to find and to return NSEC3 data). The unnecessary
   processing step that was causing this delay has now been removed.
   :gl:`#1834`

-  ``named`` could crash with an assertion failure if the name of a
   database node was looked up while the database was being modified.
   :gl:`#1857`

-  When running on a system with support for Linux capabilities,
   ``named`` drops root privileges very soon after system startup. This
   was causing a spurious log message, ``unable to set effective uid to
   0: Operation not permitted``, which has now been silenced.
   :gl:`#1042` :gl:`#1090`

-  A possible deadlock in ``lib/isc/unix/socket.c`` was fixed.
   :gl:`#1859`

-  Previously, ``named`` did not destroy some mutexes and conditional
   variables in netmgr code, which caused a memory leak on FreeBSD. This
   has been fixed. :gl:`#1893`

-  A data race in ``lib/dns/resolver.c:log_formerr()`` that could lead
   to an assertion failure was fixed. :gl:`#1808`

-  Previously, ``provide-ixfr no;`` failed to return up-to-date
   responses when the serial number was greater than or equal to the
   current serial number. :gl:`#1714`

-  A bug in dnstap initialization could prevent some dnstap data from
   being logged, especially on recursive resolvers. :gl:`#1795`

-  A bug in dnssec-policy keymgr was fixed, where the check for the
   existence of a given key's successor would incorrectly return
   ``true`` if any other key in the keyring had a successor. :gl:`#1845`

-  With dnssec-policy, when creating a successor key, the "goal" state
   of the current active key (the predecessor) was not changed and thus
   never removed from the zone. :gl:`#1846`

-  When ``named-checkconf -z`` was run, it would sometimes incorrectly
   set its exit code. It reflected the status of the last view found; if
   zone-loading errors were found in earlier configured views but not in
   the last one, the exit code indicated success. Thanks to Graham
   Clinch. :gl:`#1807`

- ``named-checkconf -p`` could include spurious text in
  ``server-addresses`` statements due to an uninitialized DSCP value.
  This has been fixed. :gl:`#1812`

-  When built without LMDB support, ``named`` failed to restart after a
   zone with a double quote (") in its name was added with ``rndc
   addzone``. Thanks to Alberto Fernández. :gl:`#1695`

-  The ARM has been updated to indicate that the TSIG session key is
   generated when named starts, regardless of whether it is needed.
   :gl:`#1842`

.. _Read the Docs: https://bind9.readthedocs.io/
