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

.. _relnotes_known_issues:

Known Issues
------------

- On some platforms, including FreeBSD, :iscman:`named` must be run as
  root to use the :iscman:`rndc` control channel on a privileged port
  (i.e., with a port number less than 1024; this includes the default
  :iscman:`rndc` :rndcconf:ref:`port`, 953). Currently, using the
  :option:`named -u` option to switch to an unprivileged user makes
  :iscman:`rndc` unusable. This will be fixed in a future release; in
  the meantime, ``mac_portacl`` can be used as a workaround, as
  documented in https://kb.isc.org/docs/aa-00621. :gl:`#4793`
