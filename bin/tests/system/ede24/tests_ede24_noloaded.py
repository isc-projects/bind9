# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os

from ede24.common import check_ns2_ready, check_soa_servfail_ede24


def test_ede24_noloaded(named_port, ns1, ns2):
    check_ns2_ready(ns2, named_port)

    # Stop all servers, and we'll restart only ns2.
    ns1.stop()
    ns2.stop()
    with ns2.watch_log_from_here() as watcher:
        ns2.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line("failure trying primary 10.53.0.1")

    # ns2 attempts an XFR but ns1 since is off the zone DB can't be loaded.
    check_soa_servfail_ede24("zone not loaded")
