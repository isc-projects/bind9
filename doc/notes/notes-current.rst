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

Security Fixes
~~~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Initial support for accepting the PROXYv2 protocol in all currently
  implemented DNS transports in :iscman:`named` and complementary
  support for sending it in :iscman:`dig` are included into this
  release. Please consult the related documentation for additional
  details.
  :gl:`#4388`

Removed Features
~~~~~~~~~~~~~~~~

- None.

- The support for AES algorithm for DNS cookies has been removed.
  :gl:`#4421`

- The ``resolver-nonbackoff-tries`` and ``resolver-retry-interval`` options
  have been removed. Using them is now a fatal error. :gl:`#4405`

Feature Changes
~~~~~~~~~~~~~~~

- The maximum number of allowed NSEC3 iterations for validation has been
  lowered from 150 to 50. DNSSEC responses containing NSEC3 records with
  iteration counts greater than 50 are now treated as insecure.  :gl:`#4363`

- The number of NSEC3 iterations that can be configured for a zone must be 0.
  :gl:`#4363`

Bug Fixes
~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
