.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.5
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- New ``rndc`` command ``rndc dnssec -status`` that shows the current
  DNSSEC policy and keys in use, the key states and rollover status.
  [GL #1612]

Bug Fixes
~~~~~~~~~

- The DS set returned by ``dns_keynode_dsset()`` was not thread-safe.
  This could result in an INSIST being triggered. [GL #1926]

- Properly handle missing ``kyua`` command so that ``make check`` does
  not fail unexpectedly when CMocka is installed, but Kyua is not.
  [GL #1950]

- The ``primary`` and ``secondary`` keywords, when used as parameters for
  ``check-names``, were not processed correctly and were being ignored.
  [GL #1949]

- 'rndc dnstap -roll <value>' was not limiting the number of saved
  files to <value>. [GL !3728]

- The validator could fail to accept a properly signed RRset if an
  unsupported algorithm appeared earlier in the DNSKEY RRset than a
  supported algorithm.  It could also stop if it detected a malformed
  public key. [GL #1689]

- The ``blackhole`` ACL was inadvertently disabled with respect to
  client queries. Blocked IP addresses were not used for upstream
  queries but queries from those addresses could still be answered.
  [GL #1936]

- ``named`` would crash on shutdown when new ``rndc`` connection is received at
  the same time as shutting down. [GL #1747]

- Fix assertion failure when server is under load and root zone is not yet
  loaded. [GL #1862]
