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

from ede24.common import check_ns2_ready, check_soa_noerror, check_soa_servfail_ede24

import isctest


def test_ede24_expired(named_port, ns1, ns2):
    check_ns2_ready(ns2, named_port)

    # Stop the primary and wait for expiration of the zone in the secondary.
    with ns2.watch_log_from_here() as watcher:
        ns1.stop()
        log_sequence = [
            " zone foo.fr/IN: expired",
            " zone foo.fr/IN: stop zone timer",
        ]
        watcher.wait_for_sequence(log_sequence)

    # ns2 can't answer anymore.
    check_soa_servfail_ede24("zone expired")

    # Restart the primary and wait for the zone to be back up again.
    with ns2.watch_log_from_here() as watcher:
        ns1.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line(
            isctest.transfer.transfer_message(
                "foo.fr", "10.53.0.1", "Transfer status: success", named_port
            )
        )
    check_soa_noerror()
