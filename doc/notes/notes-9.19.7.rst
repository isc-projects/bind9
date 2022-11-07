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

Notes for BIND 9.19.7
---------------------

New Features
~~~~~~~~~~~~

- The :any:`check-svcb` option has been added to control the checking of
  additional constraints on SVCB records. This change affects
  :iscman:`named`, :iscman:`named-checkconf`, :iscman:`named-checkzone`,
  :iscman:`named-compilezone`, and :iscman:`nsupdate`. :gl:`#3576`

Feature Changes
~~~~~~~~~~~~~~~

- On Linux, libcap is now a required dependency to help :iscman:`named`
  keep needed privileges. :gl:`#3583`

Bug Fixes
~~~~~~~~~

- Previously, BIND failed to start on Solaris-based systems with
  hundreds of CPUs. This has been fixed. :gl:`#3563`

- In certain resolution scenarios, quotas could be erroneously reached
  for servers, including any configured forwarders, resulting in
  SERVFAIL answers being sent to clients. This has been fixed.
  :gl:`#3598`

- Previously, the port in remote servers such as in :any:`primaries` and
  :any:`parental-agents` could be wrongly configured because of an
  inheritance bug. This has been fixed. :gl:`#3627`

- Previously, if Internet connectivity issues were experienced during
  the initial startup of :iscman:`named`, a BIND resolver with
  :any:`dnssec-validation` set to ``auto`` could enter into a state
  where it would not recover without stopping :iscman:`named`, manually
  deleting the ``managed-keys.bind`` and ``managed-keys.bind.jnl``
  files, and starting :iscman:`named` again. This has been fixed.
  :gl:`#2895`

- A crash was fixed that happened when a :any:`dnssec-policy` zone that
  used NSEC3 was reconfigured to enable :any:`inline-signing`.
  :gl:`#3591`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
