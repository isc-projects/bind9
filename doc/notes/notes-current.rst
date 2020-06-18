.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.3
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

- Disable and disallow static linking of BIND 9 binaries and libraries
  as BIND 9 modules require ``dlopen()`` support and static linking also
  prevents using security features like read-only relocations (RELRO) or
  address space layout randomization (ASLR) which are important for
  programs that interact with the network and process arbitrary user
  input. [GL #1933]

Bug Fixes
~~~~~~~~~

- The DS set returned by ``dns_keynode_dsset()`` was not thread-safe.
  This could result in an INSIST being triggered. [GL #1926]

- The ``primary`` and ``secondary`` keywords, when used as parameters for
  ``check-names``, were not processed correctly and were being ignored.
  [GL #1949]

- 'rndc dnstap -roll <value>' was not limiting the number of saved
  files to <value>. [GL !3728]

- The validator could fail to accept a properly signed RRset if an
  unsupported algorithm appeared earlier in the DNSKEY RRset than a
  supported algorithm.  It could also stop if it detected a malformed
  public key. [GL #1689]
