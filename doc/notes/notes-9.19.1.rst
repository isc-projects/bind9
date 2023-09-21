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

Notes for BIND 9.19.1
---------------------

Security Fixes
~~~~~~~~~~~~~~

- Previously, TLS socket objects could be destroyed prematurely, which
  triggered assertion failures in :iscman:`named` instances serving
  DNS-over-HTTPS (DoH) clients. This has been fixed.

  ISC would like to thank Thomas Amgarten from arcade solutions ag for
  bringing this vulnerability to our attention. :cve:`2022-1183`
  :gl:`#3216`

New Features
~~~~~~~~~~~~

- Catalog Zones schema version 2, as described in the
  "DNS Catalog Zones" IETF draft version 5 document, is now supported by
  :iscman:`named`. All of the previously supported BIND-specific catalog
  zone custom properties (:any:`primaries`, :any:`allow-query`, and
  :any:`allow-transfer`), as well as the new Change of Ownership (``coo``)
  property, are now implemented. Schema version 1 is still supported,
  with some additional validation rules applied from schema version 2:
  for example, the :any:`version` property is mandatory, and a member zone
  PTR RRset must not contain more than one record. In the event of a
  validation error, a corresponding error message is logged to help with
  diagnosing the problem. :gl:`#3221` :gl:`#3222` :gl:`#3223`
  :gl:`#3224` :gl:`#3225`

- Support DNS Extended Errors (:rfc:`8914`) ``Stale Answer`` and
  ``Stale NXDOMAIN Answer`` when stale answers are returned from cache.
  :gl:`#2267`

- The Object Identifier (OID) embedded at the start of a PRIVATEOID
  public key in a KEY, DNSKEY, CDNSKEY, or RKEY resource records is now
  checked to ensure that it is valid when reading from zone files or
  receiving data on the wire. The Object Identifier is now printed when
  the ``dig +rrcomments`` option is used. Similarly, the name embedded
  at the start of a PRIVATEDNS public key is also checked for validity.
  :gl:`#3234`

- The Object Identifier (OID) embedded at the start of a PRIVATEOID
  signature in a SIG, or RRSIG resource records is now checked to
  ensure that it is valid when reading from zone files or receiving
  data on the wire.  Similarly, the name embedded at the start of
  a PRIVATEDNS public key is also checked for validity. :gl:`#3296`

Bug Fixes
~~~~~~~~~

- Previously, CDS and CDNSKEY DELETE records were removed from the zone
  when configured with the ``auto-dnssec maintain;`` option. This has
  been fixed. :gl:`#2931`

Known Issues
~~~~~~~~~~~~

- There are no new known issues with this release. See :ref:`above
  <relnotes_known_issues>` for a list of all known issues affecting this
  BIND 9 branch.
