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

.. iscman:: dnssec-ksr
.. program:: dnssec-ksr
.. _man_dnssec-ksr:

dnssec-ksr - Create signed key response (SKR) files for offline KSK setups
--------------------------------------------------------------------------

Synopsis
~~~~~~~~

:program:`dnssec-ksr [**-h**]` [**-V**] [**-v** level]

Description
~~~~~~~~~~~

The :program:`dnssec-ksr` command creates signed key responses (SKRs) that can
be loaded by a DNS authoritative server. An SKR is a RRset of type DNSKEY,
CDNSKEY, or CDS, with signatures from a key that is typically offline during
normal operation.

Options
~~~~~~~

.. option:: -h

   This option prints a short summary of the options and arguments to
   :program:`dnssec-ksr`.

.. option:: -V

   This option prints version information.

.. option:: -v level

   This option sets the debugging level. Level 1 is intended to be usefully
   verbose for general users; higher levels are intended for developers.

Exit Status
~~~~~~~~~~~

The :program:`dnssec-ksr` command exits 0 on success, or non-zero if an error
occurred.

Examples
~~~~~~~~

To do.

See Also
~~~~~~~~

:iscman:`dnssec-keygen(8) <dnssec-keygen>`,
:iscman:`dnssec-signzone(8) <dnssec-signzone>`,
BIND 9 Administrator Reference Manual.
