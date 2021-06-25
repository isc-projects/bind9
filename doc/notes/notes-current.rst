.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.19
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Automatic KSK rollover: A new configuration option ``parental-agents`` is
  added to add a list of servers to a zone that can be used for checking DS
  presence. :gl:`#1126`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- IP fragmentation on outgoing UDP sockets has been disabled.  Errors from
  sending DNS messages larger than the specified path MTU are properly handled;
  ``named`` now sends back empty DNS messages with the TC (TrunCated) bit set,
  forcing the DNS client to fall back to TCP.  :gl:`#2790`

  ``named`` now sets the DON'T FRAGMENT flag on outgoing UDP packets.  According
  to the measurements done by multiple parties this should not be causing any
  operational problems as most of the Internet "core" is able to cope with IP
  message sizes between 1400-1500 bytes, the 1232 size was picked as a
  conservative minimal number that could be changed by the DNS operator to a
  estimated path MTU minus the estimated header space. In practice, the smallest
  MTU witnessed in the operational DNS community is 1500 octets, the Ethernet
  maximum payload size, so a a useful default for maximum DNS/UDP payload size
  on reliable networks would be 1432. [GL #2183]

Bug Fixes
~~~~~~~~~

- Fixed a bug that caused the NSEC salt to be changed for KASP zones on
  every startup. :gl:`#2725`

- Signed, insecure delegation responses prepared by ``named`` either
  lacked the necessary NSEC records or contained duplicate NSEC records
  when both wildcard expansion and CNAME chaining were required to
  prepare the response. This has been fixed. :gl:`#2759`

- A deadlock at startup was introduced when fixing :gl:`#1875` because when
  locking key files for reading and writing, "in-view" logic was not taken into
  account. This has been fixed. :gl:`#2783`

- Checking of ``dnssec-policy`` was broken. The checks failed to account for
  ``dnssec-policy`` inheritance. :gl:`#2780`
