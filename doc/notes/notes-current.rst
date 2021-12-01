.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, you can obtain one at https://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- Set Extended DNS Error Code 18 - Prohibited if query access is denied to the
  specific client. :gl:`#1836`

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The ``allow-transfers`` option was extended to accept additional
  ``port`` and ``transport`` parameters, to further restrict zone
  transfers to a particular port and DNS transport protocol. Either of
  these options can be specified.

  For example: ``allow-transfer port 853 transport tls { any; };``
  :gl:`#2776`

- `UseSTD3ASCIIRules`_ is now disabled for IDN support. This disables additional
  validation rules for domain names in dig because applying the rules would
  silently strip characters not-allowed in hostnames such as underscore (``_``)
  or wildcard (``*``) characters.  This reverts change :gl:`!5738` from the
  previous release.  :gl:`#1610`

Bug Fixes
~~~~~~~~~

- Removing a configured ``catalog-zone`` clause from the configuration, running
  ``rndc reconfig``, then bringing back the removed ``catalog-zone`` clause and
  running ``rndc reconfig`` again caused ``named`` to crash. This has been fixed.
  :gl:`#1608`

- The resolver could hang on shutdown due to dispatch resources not being
  cleaned up when a TCP connection was reset. This has been fixed. :gl:`#3026`
