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

Notes for BIND 9.18.25
----------------------

Bug Fixes
~~~~~~~~~

- A regression in cache-cleaning code enabled memory use to grow
  significantly more quickly than before, until the configured
  :any:`max-cache-size` limit was reached. This has been fixed.
  :gl:`#4596`

- Using :option:`rndc flush` inadvertently caused cache cleaning to
  become less effective. This could ultimately lead to the configured
  :any:`max-cache-size` limit being exceeded and has now been fixed.
  :gl:`#4621`

- The logic for cleaning up cached DNS records whose TTL has expired was
  tweaked to be more aggressive. This change helps with enforcing
  :any:`max-cache-ttl` and :any:`max-ncache-ttl` in a timely manner.
  :gl:`#4591`

- A use-after-free assertion might get triggered when the overmem cache
  cleaning triggers. :gl:`#4595`

  ISC would like to thank to Jinmei Tatuya from Infoblox for bringing
  this issue to our attention.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
