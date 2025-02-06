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

.. iscman:: named-makejournal
.. program:: named-makejournal
.. _man_named-makejournal:

named-makejournal - create a journal from zone files
----------------------------------------------------

Synopsis
~~~~~~~~

:program:`named-makejournal` [-hm] {origin} {oldfile} {newfile} [journal]

Description
~~~~~~~~~~~

:program:`named-makejournal` scans the contents of two zone files for
the domain specified by ``origin``, compares them, and writes the
differences into a journal file.  The resulting journal file could
then be used by :iscman:`named` to load the zone and provide incremental
zone transfers.

Both ``oldfile`` and ``newfile`` must be successfully loadable as zone
databases, and ``newfile`` must have a higher SOA serial number than
``oldfile``.

If the optional argument ``journal`` is not specified, then the journal
file name will be formed by appending the extension ``.jnl`` to the
zone file name specified as ``oldfile``.

If the journal file already exists, then it will be applied to ``oldfile``
immediately after loading. The difference between the resulting zone and
the one in ``newfile`` will then be appended onto the end of the journal.
This allows creation of journal files with multiple transactions, by
running ``named-makejournal`` multiple times, updating ``newfile`` each
time.

Options
~~~~~~~

.. option:: -h

   Print a usage summary.

.. option:: -m

   Enables memory usage debugging.

See Also
~~~~~~~~

:iscman:`named(8) <named>`, :iscman:`named-journalprint(1) <named-journalprint>`, BIND 9 Administrator Reference Manual.
