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

.. iscman:: named-wireformat
.. program:: named-wireformat
.. _man_named-wireformat:

named-wireformat - parse DNS wire format messages
-------------------------------------------------

Synopsis
~~~~~~~~

:program:`named-wireformat` [**-b**] [**-d**] [**-h**] [**-m** flag] [**-p**] [**-r**] [**-s**] [**-t**] [{filename}]

Description
~~~~~~~~~~~

:program:`named-wireformat` reads a DNS message in wire format, either
in hexidecimal form or as raw data, from a file or from standard input,
and translates it to text format to check whether it is formatted correctly.

Options
~~~~~~~

.. option:: -b

   Use best-effort parsing. Errors in message content will be
   ignored, so long as the message itself can still be parsed as valid
   DNS wire data.

.. option:: -d

   Read input as raw binary data instead of hexidecimal text.

.. option:: -h

   Print out the help menu.

.. option:: -m flag

   Turn on memory debugging flags. Possible flags are ``usage``,
   ``trace`` and ``record``.

.. option:: -p

   Preserve the order of records in the message, instead of sorting
   by name and type.

.. option:: -r

   After parsing and displaying the input message, render it back to wire
   format, parse that, and display it again. This is used to confirm
   that parsing and rendering are idempotent.

.. option:: -s

   Print memory statistics on shutdown.

.. option:: -t

   Parse the input as a TCP DNS message, with a two-byte length header.

Arguments
~~~~~~~~~

.. option:: filename

   If specified, the message to be parsed is read from this file.
   Otherwise, it is read from the standard input.

See Also
~~~~~~~~

:iscman:`named-rrchecker(8) <named-rrchecker>`,
BIND 9 Administrator Reference Manual.
