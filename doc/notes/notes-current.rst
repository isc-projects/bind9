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

Notes for BIND 9.18.7
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

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Zones using ``dnssec-policy`` now require dynamic DNS or
  ``inline-signing`` to be configured explicitly :gl:`#3381`.

- When reconfiguring ``dnssec-policy`` from using NSEC with an NSEC-only DNSKEY
  algorithm (e.g. RSASHA1) to a policy that uses NSEC3, BIND will no longer fail
  to sign the zone, but keep using NSEC for a little longer until the offending
  DNSKEY records have been removed from the zone, then switch to using NSEC3.
  :gl:`#3486`

- Implement a backwards compatible approach for encoding the internationalized
  domain names (IDN) in dig, and convert the domain to IDNA2008 form, and if
  that fails try the IDNA2003 conversion. :gl:`#3485`

Bug Fixes
~~~~~~~~~

- Fix a serve-stale bug, where BIND would try to return stale data from cache
  for lookups that received duplicate queries or queries that would be dropped.
  This bug resulted in premature SERVFAIL responses, and has now been resolved.
  :gl:`#2982`
