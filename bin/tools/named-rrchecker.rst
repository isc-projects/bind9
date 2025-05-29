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

   This option specifies the origin to be used when interpreting
   the record.

.. option:: -p

   This option prints out the resulting record in canonical form. If there
   is no canonical form defined, the record is printed in unknown
   record format.

.. option:: -u

   This option prints out the resulting record in unknown record form.

.. option:: -C, -T, -P

   These options print out the known class, standard type,
   and private type mnemonics, respectively.

See Also
~~~~~~~~

:rfc:`1034`, :rfc:`1035`, :rfc:`3957`, :iscman:`named(8) <named>`.
