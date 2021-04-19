.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.16.15
----------------------

Bug Fixes
~~~~~~~~~

- If zone journal files written by BIND 9.16.11 or earlier were present
  when BIND was upgraded to BIND 9.16.13 or BIND 9.16.14, the zone file
  for that zone could have been inadvertently rewritten with the current
  zone contents. This caused the original zone file structure (e.g.
  comments, ``$INCLUDE`` directives) to be lost, although the zone data
  itself was preserved. [GL #2623]
