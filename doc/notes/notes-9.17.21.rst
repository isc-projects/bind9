.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.21
----------------------

New Features
~~~~~~~~~~~~

- The ``allow-transfer`` option was extended to accept additional
  ``port`` and ``transport`` parameters, to further restrict zone
  transfers to a particular port and/or DNS transport protocol.
  :gl:`#2776`

- Extended DNS Error Code 18 - Prohibited (see :rfc:`8194` section
  4.19) is now set if query access is denied to the specific client.
  :gl:`#1836`

Feature Changes
~~~~~~~~~~~~~~~

- Aggressive Use of DNSSEC-Validated Cache (``synth-from-dnssec``, see
  :rfc:`8198`) is now enabled by default again, after having been
  disabled in BIND 9.14.8. The implementation of this feature was
  reworked to achieve better efficiency and tuned to ignore certain
  types of broken NSEC records. Negative answer synthesis is currently
  only supported for zones using NSEC. :gl:`#1265`

- The `UseSTD3ASCIIRules`_ flag is now disabled again for libidn2
  function calls. Applying additional validation rules for domain names
  in ``dig`` (a change introduced in the previous BIND 9 release) caused
  characters which are disallowed in hostnames (e.g. underscore ``_``,
  wildcard ``*``) to be silently stripped. That change was reverted.
  :gl:`#1610`

- Previously, when an incoming TCP connection could not be accepted
  because the client closed the connection early, an error message of
  ``TCP connection failed: socket is not connected`` was logged. This
  message has been changed to ``Accepting TCP connection failed: socket
  is not connected``. The severity level at which this type of message
  is logged has also been changed from ``error`` to ``info`` for the
  following triggering events: ``socket is not connected``, ``quota
  reached``, and ``soft quota reached``. :gl:`#2700`

- ``dnssec-dsfromkey`` no longer generates DS records from revoked keys.
  :gl:`#853`

.. _UseSTD3ASCIIRules: http://www.unicode.org/reports/tr46/#UseSTD3ASCIIRules

Bug Fixes
~~~~~~~~~

- Removing a configured ``catalog-zone`` clause from the configuration,
  running ``rndc reconfig``, then bringing back the removed
  ``catalog-zone`` clause and running ``rndc reconfig`` again caused
  ``named`` to crash. This has been fixed. :gl:`#1608`

- The resolver could hang on shutdown due to dispatch resources not
  being cleaned up when a TCP connection was reset, or due to dependency
  loops in the ADB or the DNSSEC validator. This has been fixed.
  :gl:`#3026` :gl:`#3040`
