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


def test_configloading_log(servers):
    """
    This test is a "guard/warning" to make sure the named.conf loading
    (parsing) is done outside of the exclusive mode (so, named is still able to
    answer queries and operating normally in case of configuration reload). It
    is currently based on logging, so it's quite brittle.
    """

    server = servers["ns1"]
    log_sequence = [
        "load_configuration",
        "parsing user configuration from ",
        "apply_configuration",
        "loop exclusive mode: starting",
    ]

    with server.watch_log_from_start() as watcher:
        watcher.wait_for_sequence(log_sequence)

    with server.watch_log_from_here() as watcher:
        server.rndc("reconfig")
        watcher.wait_for_sequence(log_sequence)

    with server.watch_log_from_here() as watcher:
        server.rndc("reload")
        watcher.wait_for_sequence(log_sequence)
