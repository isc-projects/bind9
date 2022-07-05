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

Notes for BIND 9.19.3
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

- The ``glue-cache`` *option* has been removed. The glue cache *feature*
  still works and is now permanently *enabled*. :gl:`#2147`

Feature Changes
~~~~~~~~~~~~~~~

- The :option:`dnssec-signzone -H` default value has been changed to 0 additional
  NSEC3 iterations. This change aligns the :iscman:`dnssec-signzone` default with
  the default used by the :ref:`dnssec-policy <dnssec_policy_grammar>` feature.
  At the same time, documentation about NSEC3 has been aligned with
  `Best Current Practice
  <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance-10>`__.
  :gl:`#3395`

Bug Fixes
~~~~~~~~~

- It was possible for a catalog zone consumer to process a catalog zone member
  zone when there was a configured pre-existing forward-only forward zone with
  the same name. This has been fixed. :gl:`#2506`.

- Fix the assertion failure caused by TCP connection closing between the
  connect (or accept) and the read from the socket. :gl:`#3400`

- When grafting on non-delegated namespace, synth-from-dnssec could incorrectly
  synthesise non-existance of records within the grafted in namespace using
  NSEC records from higher zones. :gl:`#3402`
