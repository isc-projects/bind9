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

.. highlight: console

.. iscman:: named-rrchecker
.. program:: named-rrchecker
.. _man_named-rrchecker:

named-rrchecker - syntax checker for individual DNS resource records
--------------------------------------------------------------------

Synopsis
~~~~~~~~

:program:`named-rrchecker` [**-h**] [**-o** origin] [**-p**] [**-u**] [**-C**] [**-T**] [**-P**]

Description
~~~~~~~~~~~

:program:`named-rrchecker` reads a single DNS resource record (RR) from standard
input and checks whether it is syntactically correct.

The input format is a minimal subset of the DNS zone file format. The entire input must be:
  CLASS TYPE RDATA

* Input must not start with an owner (domain) name
* The `CLASS` field is mandatory (typically ``IN``).
* The `TTL` field **must not** be present.
* RDATA format is specific to each RRTYPE.
* Leading and trailing whitespace in each field is ignored.

Format details can be found in :rfc:`1035#section-5.1` under ``<rr>``
specification. :rfc:`3597` format is also accepted in any of the input fields.


Options
~~~~~~~

.. option:: -o origin

   This option specifies the origin to be used when interpreting names in the record:
   it defaults to root (`.`). The specified origin is always taken as an absolute name.

.. option:: -p

   This option prints out the resulting record in canonical form. If there
   is no canonical form defined, the record is printed in :rfc:`3597` unknown
   record format.

.. option:: -u

   This option prints out the resulting record in :rfc:`3597` unknown record
   format.

.. option:: -C, -T, -P

   These options do not read input. They print out known classes, standard types,
   and private type mnemonics. Each item is printed on a separate line.
   The resulting list of private types may be empty

.. option:: -h

   This option prints out the help menu.


See Also
~~~~~~~~

:rfc:`1034`, :rfc:`1035`, :rfc:`3957`, :iscman:`named(8) <named>`.
