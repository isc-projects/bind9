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

Notes for BIND 9.18.50
----------------------

Removed Features
~~~~~~~~~~~~~~~~

- Remove ineffective TCP fallback after repeated UDP timeouts.

  When an authoritative server failed to respond to two consecutive UDP
  queries, :iscman:`named` marked the next retry as TCP but still sent
  it over UDP, producing misleading dnstap records. The ineffective
  retry path has been removed; a corrected TCP fallback will be restored
  in future BIND 9 versions. :gl:`#5529`

Feature Changes
~~~~~~~~~~~~~~~

- Fall back to TCP on receipt of a UDP response with a mismatched query ID.

  BIND used to wait silently for the correct DNS message ID on a UDP
  fetch, even after receiving a response from the expected server with
  the wrong ID, leaving room for off-path spoofing attempts to keep
  guessing within that window.  The resolver now retries the fetch over
  TCP on the first such response, and a new ``MismatchTCP`` statistics
  counter tracks how often the fallback fires. :gl:`#5449`

Bug Fixes
~~~~~~~~~

- Fix DNS64 owner case after DNAME restart.

  When BIND 9 was configured to use DNS64 and encountered a DNAME
  redirect, it could end up using freed memory for the DNS response
  owner name. This caused the response to contain corrupted data. This
  fix ensures the correct owner name is used when constructing the
  synthesized response after a DNAME redirect. :gl:`#5934`

- Clear REDIRECT flag when it isn't needed.

  When :any:`nxdomain-redirect` is in use, and a recursive query is used
  to get the redirected answer, a flag is set to distinguish it from a
  normal recursive response. Previously, that flag was left set
  afterward, which could trigger an assertion if a normal recursive
  query was sent later on behalf of the same client: for example,
  because the :any:`filter-aaaa` plugin was in use.  This has been
  fixed. :gl:`#5936`
