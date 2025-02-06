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

:program:`named-makejournal` {origin} {oldfile} {newfile} {journal}

Description
~~~~~~~~~~~

:program:`named-makejournal` scans the contents of two zone files for
the same domain, compares them, and writes the differences into a
journal file. The resulting journal file could then be used by a
:iscman:`named` server to load the zone and provide incremental
zone transfers.

See Also
~~~~~~~~

:iscman:`named(8) <named>`, :iscman:`named-journalprint(1) <named-journalprint>`, BIND 9 Administrator Reference Manual.
