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

Notes for BIND 9.19.25
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Malicious DNS client that sends many queries over TCP but never reads
  responses can cause server to respond slowly or not respond at all for other
  clients. :cve:`2024-0760` :gl:`#4481`

- Excessively large resource record sets can be crafted to slow down
  database processing. This has been addressed by adding a configurable
  limit to the number of records that can be stored per name and type in
  a cache or zone database. The default is 100, but it can be tuned with
  the new ``max-records-per-type`` option. :gl:`#497` :gl:`#3405`

  An excessively large number of resource record types for a single owner name can
  be crafted to slow down database processing. This has been addressed by adding
  a configurable limit to the number of records that can be stored per name and
  type in a cache or zone database.  The default is 100, and can be tuned with
  the new ``max-rrtypes-per-name`` option. :cve:`2024-1737` :gl:`#3403`

  ISC would like to thank Toshifumi Sakaguchi who independently discovered
  and responsibly reported the issue to ISC. :gl:`#4548`

- A malicious DNS client that sends many queries with a SIG(0)-signed message
  can cause server to respond slowly or not respond at all for other clients.
  :cve:`2024-1975` :gl:`#4480`

- Due to a logic error, lookups that trigger serving stale data and require
  lookups in local authoritative zone data may result in an assertion failure.
  This has been fixed. :cve:`2024-4076` :gl:`#4507`

New Features
~~~~~~~~~~~~

- Added a new statistics variable ``recursive high-water`` that reports
  the maximum number of simultaneous recursive clients BIND has handled
  while running. :gl:`#4668`

Feature Changes
~~~~~~~~~~~~~~~

- Outgoing zone transfers are no longer enabled by default. An explicit
  :any:`allow-transfer` ACL must now be set at the :any:`zone`, :any:`view` or
  :namedconf:ref:`options` level to enable outgoing transfers. :gl:`#4728`

Bug Fixes
~~~~~~~~~

- An RPZ response's SOA record TTL was set to 1 instead of the SOA TTL, if
  ``add-soa`` was used. This has been fixed. :gl:`#3323`

- Potential data races were found in our DoH implementation related
  to HTTP/2 session object management and endpoints set object
  management after reconfiguration. These issues have been
  fixed. :gl:`#4473`

  ISC would like to thank Dzintars and Ivo from nic.lv for bringing
  this to our attention.

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
