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

- Long-running tasks in offloaded threads (e.g. loading RPZ zones or
  processing zone transfers) may block the resolution of queries during
  these operations and cause the queries to time out.

  To work around the issue, the ``UV_THREADPOOL_SIZE`` environment
  variable can be set to a larger value before starting :iscman:`named`.
  The recommended value is the number of RPZ zones (or number of
  transfers) plus the number of threads BIND should use, which is
  typically the number of CPUs. :gl:`#4898`
