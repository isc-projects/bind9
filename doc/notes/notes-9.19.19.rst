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

Notes for BIND 9.19.19
----------------------

New Features
~~~~~~~~~~~~

- Initial support for the PROXYv2 protocol was added. :iscman:`named`
  can now accept PROXYv2 headers over all currently implemented DNS
  transports and :iscman:`dig` can insert these headers into the queries
  it sends. Please consult the related documentation
  (:any:`allow-proxy`, :any:`allow-proxy-on`, :any:`listen-on`, and
  :any:`listen-on-v6` for :iscman:`named`, :option:`dig +proxy` and
  :option:`dig +proxy-plain` for :iscman:`dig`) for additional details.
  :gl:`#4388`

Removed Features
~~~~~~~~~~~~~~~~

- Support for using AES as the DNS COOKIE algorithm (``cookie-algorithm
  aes;``) has been removed. The only supported DNS COOKIE algorithm is
  now the current default, SipHash-2-4. :gl:`#4421`

- The ``resolver-nonbackoff-tries`` and ``resolver-retry-interval``
  statements have been removed. Using them is now a fatal error.
  :gl:`#4405`

Feature Changes
~~~~~~~~~~~~~~~

- The maximum number of NSEC3 iterations allowed for validation purposes
  has been lowered from 150 to 50. DNSSEC responses containing NSEC3
  records with iteration counts greater than 50 are now treated as
  insecure. :gl:`#4363`

- Following :rfc:`9276` recommendations, :any:`dnssec-policy` now only
  allows an NSEC3 iteration count of 0 for the DNSSEC-signed zones using
  NSEC3 that the policy manages. :gl:`#4363`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
