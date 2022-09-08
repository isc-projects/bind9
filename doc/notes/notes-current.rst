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

Notes for BIND 9.19.5
---------------------

Security Fixes
~~~~~~~~~~~~~~

- Previously, there was no limit to the number of database lookups
  performed while processing large delegations, which could be abused to
  severely impact the performance of :iscman:`named` running as a
  recursive resolver. This has been fixed. (CVE-2022-2795)

  ISC would like to thank Yehuda Afek from Tel-Aviv University and Anat
  Bremler-Barr & Shani Stajnrod from Reichman University for bringing
  this vulnerability to our attention. :gl:`#3394`

- When an HTTP connection was reused to request statistics from the
  stats channel, the content length of successive responses could grow
  in size past the end of the allocated buffer. This has been fixed.
  (CVE-2022-2881) :gl:`#3493`

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Worker threads' event loops are now managed by a new "loop maanger" API,
  significantly changing the architecture of the task, timer and networking
  systems for improved performance and code flow. :gl:`#3508`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- Response Rate Limiting (RRL) code now treats all QNAMEs that are
  subject to wildcard processing within a given zone as the same name,
  to prevent circumventing the limits enforced by RRL. :gl:`#3459`

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
