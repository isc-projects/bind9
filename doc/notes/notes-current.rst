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

Feature Changes
~~~~~~~~~~~~~~~

- None.

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
