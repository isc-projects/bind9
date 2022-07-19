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

Notes for BIND 9.16.32
----------------------

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

- DNSSEC ``RSASHA1`` and ``NSEC3RSASHA1`` are automatically disabled
  on systems (e.g. RHEL9) where they are disallowed by the security
  policy.  Primary zones using those algorithms need to be moved
  off of them prior to running on these systems as graceful migration
  to different DNSSEC algorithms is not possible when RSASHA1 is
  disallowed by the OS. :gl:`#3469`

- Fetch limit log messages have been improved to provide more complete
  information. Specifically, the final values of allowed and spilled fetches
  will now be logged before the counter object gets destroyed. :gl:`#3461`

Bug Fixes
~~~~~~~~~

- Non-dynamic zones that inherit dnssec-policy from the view or
  options level were not marked as inline-signed, and thus were never
  scheduled to be re-signed. This is now fixed. :gl:`#3438`

- The old ``max-zone-ttl`` zone option was meant to be superseded by
  the ``max-zone-ttl`` option in ``dnssec-policy``; however, the latter
  option was not fully effective. This has been corrected: zones will
  not load if they contain TTLs greater than the limit configured in
  ``dnssec-policy``. In zones with both the old ``max-zone-ttl``
  option and ``dnssec-policy`` configured, the old option will be
  ignored, and a warning will be generated. :gl:`#2918`

- Fix `rndc dumpdb -expired` to include expired RRsets, even if the cache
  cleaning time window has passed. This will now show expired RRsets that are
  stuck in the cache. :gl:`#3462`
