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

Notes for BIND 9.19.12
----------------------

Security Fixes
~~~~~~~~~~~~~~

- An error in DNS message processing introduced in development version
  9.19.11 could cause BIND and its utilities to crash if the maximum
  permissible number of DNS labels were present. This has been fixed.
  :gl:`#3998`

Known Issues
~~~~~~~~~~~~

- Loading a large number of zones is significantly slower in BIND
  9.19.12 than in the previous development releases due to a new data
  structure being used for storing information about the zones to serve.
  This slowdown is considered to be a bug and will be addressed in a
  future BIND 9.19.x development release. :gl:`#4006`

- A flaw in reworked code responsible for accepting TCP connections may
  cause a visible performance drop for TCP queries on some platforms,
  notably FreeBSD.  This issue will be fixed in a future BIND 9.19.x
  development release. :gl:`#3985`

- See :ref:`above <relnotes_known_issues>` for a list of all known issues
  affecting this BIND 9 branch.

New Features
~~~~~~~~~~~~

- BIND now depends on `liburcu`_, Userspace RCU, for lock-free data
  structures. :gl:`#3934`

- The new command-line :option:`delv +ns` option activates name server
  mode, to more accurately reproduce the behavior of :iscman:`named`
  when resolving a query. In this mode, :iscman:`delv` uses an internal
  recursive resolver rather than an external server. All messages sent
  and received during the resolution and validation process are logged.
  This can be used in place of :option:`dig +trace`. :gl:`#3842`

- A new configuration option, :any:`checkds`, has been introduced. When
  set to ``yes``, it detects :any:`parental-agents` automatically by
  resolving the parent NS records. These name servers are queried to
  check the DS RRset during a KSK rollover initiated by
  :any:`dnssec-policy`. :gl:`#3901`

.. _`liburcu`: https://liburcu.org/

Removed Features
~~~~~~~~~~~~~~~~

- The TKEY Mode 2 (Diffie-Hellman Exchanged Keying Mode) has been
  removed and using TKEY Mode 2 is now a fatal error. Users are advised
  to switch to TKEY Mode 3 (GSS-API). :gl:`#3905`

- Zone type ``delegation-only``, and the ``delegation-only`` and
  ``root-delegation-only`` statements, have been removed. Using them is
  a configuration error.

  These statements were created to address the SiteFinder controversy,
  in which certain top-level domains redirected misspelled queries to
  other sites instead of returning NXDOMAIN responses. Since top-level
  domains are now DNSSEC-signed, and DNSSEC validation is active by
  default, the statements are no longer needed. :gl:`#3953`

Feature Changes
~~~~~~~~~~~~~~~

- The log message ``resolver priming query complete`` has been moved
  from the INFO log level to the DEBUG(1) log level, to prevent
  :iscman:`delv` from emitting that message when setting up its internal
  resolver. :gl:`#3842`

Bug Fixes
~~~~~~~~~

- Several bugs which could cause :iscman:`named` to crash during catalog
  zone processing have been fixed. :gl:`#3955` :gl:`#3968` :gl:`#3997`

- Performance of DNSSEC validation in zones with many DNSKEY records has
  been improved. :gl:`#3981`
