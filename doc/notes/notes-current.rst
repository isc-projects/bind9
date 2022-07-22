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

- None.

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
