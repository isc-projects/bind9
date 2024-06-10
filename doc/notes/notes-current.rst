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

Notes for BIND 9.18.28
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Malicious DNS client that sends many queries over TCP but never reads
  responses can cause server to respond slowly or not respond at all for other
  clients. :cve:`2024-0760` :gl:`#4481`

- Named could trigger an assertion failure when looking up the NS
  records of parent zones as part of looking up DS records.  This
  has been fixed. :gl:`#4661`

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- None.

Bug Fixes
~~~~~~~~~

- Potential data races were found in our DoH implementation related
  to HTTP/2 session object management and endpoints set object
  management after reconfiguration. These issues have been
  fixed. :gl:`#4473`

  ISC would like to thank Dzintars and Ivo from nic.lv for bringing
  this to our attention.

- An RPZ response's SOA record TTL was set to 1 instead of the SOA TTL, if
  ``add-soa`` was used. This has been fixed. :gl:`#3323`

- When a query related to zone maintenance (NOTIFY, SOA) timed out close
  to a view shutdown (triggered e.g. by :option:`rndc reload`),
  :iscman:`named` could crash with an assertion failure. This has been
  fixed. :gl:`#4719`

- The statistics channel counters that indicated the number of currently
  connected TCP IPv4/IPv6 clients were not properly adjusted in certain
  failure scenarios. This has been fixed. :gl:`#4742`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
