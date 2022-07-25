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

Notes for BIND 9.19.4
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

- The use of the ``max-zone-ttl`` option in ``options`` and ``zone``
  blocks has been deprecated; it should now be configured as part of
  ``dnssec-policy``. A warning is logged if this option is used in
  ``options`` or ``zone``. In a future release, it will become
  nonoperational. :gl:`#2918`

Feature Changes
~~~~~~~~~~~~~~~

- DNSSEC ``RSASHA1`` and ``NSEC3RSASHA1`` are automatically disabled
  on systems (e.g. RHEL9) where they are disallowed by the security
  policy.  Primary zones using those algorithms need to be moved
  off of them prior to running on these systems as graceful migration
  to different DNSSEC algorithms is not possible when RSASHA1 is
  disallowed by the OS. :gl:`#3469`

Bug Fixes
~~~~~~~~~

- When running as a validating resolver forwarding all queries to
  another resolver, :iscman:`named` could crash with an assertion
  failure. These crashes occurred when the configured forwarder sent a
  broken DS response and :iscman:`named` failed its attempts to find a
  proper one instead. This has been fixed. :gl:`#3439`

- A DNS compression would be applied on the root zone name if it is repeatedly
  used in the same RRSet. :gl:`#3423`

- Non-dynamic zones that inherit dnssec-policy from the view or
  options level were not marked as inline-signed, and thus were never
  scheduled to be re-signed. This is now fixed. :gl:`#3438`

- Fix `rndc dumpdb -expired` to include expired RRsets, even if the cache
  cleaning time window has passed. This will now show expired RRsets that are
  stuck in the cache. :gl:`#3462`
