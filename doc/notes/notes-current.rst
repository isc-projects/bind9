.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.6
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Add a new ``rndc`` command, ``rndc dnssec -rollover``, which triggers
  a manual rollover for a specific key. [GL #1749]

- New ``rndc`` command ``rndc dumpdb -expired`` that dumps the cache database
  to the dump-file including expired RRsets that are awaiting cleanup, for
  diagnostic purposes. [GL #1870]

Removed Features
~~~~~~~~~~~~~~~~

- None.


Feature Changes
~~~~~~~~~~~~~~~

- [DNS Flag Day 2020]: The default EDNS buffer size has been changed from 4096
  to 1232, the EDNS buffer size probing has been removed and ``named`` now sets
  the DON'T FRAGMENT flag on outgoing UDP packets.  According to the
  measurements done by multiple parties this should not be causing any
  operational problems as most of the Internet "core" is able to cope with IP
  message sizes between 1400-1500 bytes, the 1232 size was picked as a
  conservative minimal number that could be changed by the DNS operator to a
  estimated path MTU minus the estimated header space. In practice, the smallest
  MTU witnessed in the operational DNS community is 1500 octets, the Ethernet
  maximum payload size, so a a useful default for maximum DNS/UDP payload size
  on reliable networks would be 1400. [GL #2183]

Bug Fixes
~~~~~~~~~

- Updating contents of an RPZ zone which contained names spelled using
  varying letter case could cause some processing rules in that RPZ zone
  to be erroneously ignored. [GL #2169]

- `named` would report invalid memory size when running in an environment
  that doesn't properly report number of available memory pages or pagesize.
  [GL #2166]

- `named` would exit with assertion failure REQUIRE(msg->state == (-1)) in
  message.c due to a possible data race. [GL #2124]

- `named` would start continous rollovers for policies that algorithms
  Ed25519 or Ed448 due to a mismatch in created key size and expected key size.
  [GL #2171]

- Handle `UV_EOF` differently such that it is not treated as a `TCP4RecvErr` or
  `TCP6RecvErr`. [GL #2208]
