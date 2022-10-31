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

Notes for BIND 9.18.9
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

- The RecursClients statistics counter could overflow in certain resolution
  scenarios. This has been fixed. :gl:`#3584`

- BIND would fail to start on Solaris-based systems with hundreds of CPUs. This
  has been fixed. ISC would like to thank Stacey Marshall from Oracle for
  bringing this problem to our attention. :gl:`#3563`

- In certain resolution scenarios quotas could be erroneously reached for
  servers, including the configured forwarders, resulting in SERVFAIL answers
  sent to the clients. This has been fixed. :gl:`#3598`

- The port in remote servers such as in :any:`primaries` and
  :any:`parental-agents` could be wrongly configured because of an inheritance
  bug. :gl:`#3627`

- When having Internet connectivity issues during the initial startup of
  ``named``, BIND resolver with :any:`dnssec-validation` set to ``auto`` could
  enter into a state where it would not recover without stopping ``named``,
  manually deleting ``managed-keys.bind`` and ``managed-keys.bind.jnl`` files,
  and starting ``named`` again. :gl:`#2895`
