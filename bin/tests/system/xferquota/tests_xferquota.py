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

import multiprocessing
import time

import dns.message
import dns.query
import dns.zone


def _flood_unauthorized_axfrs(port, duration):
    """Child process: send unauthorized AXFR requests for `duration` seconds."""
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            msg = dns.message.make_query("quota.", "AXFR")
            dns.query.tcp(msg, "10.53.0.3", port=port, timeout=2, source="10.53.0.1")
        except Exception:  # pylint: disable=broad-exception-caught
            pass


def test_xfrquota_unauthorized_no_starve(named_port):
    """Unauthorized AXFR clients must not consume XFR-out quota (GL #3859).

    ns3 is configured with transfers-out 1 and allow-transfer { 10.53.0.2; }.
    We flood AXFR requests from unauthorized source processes (10.53.0.1) and
    verify that an authorized client (10.53.0.2) can still transfer.
    """
    with multiprocessing.Pool(10) as pool:
        pool.starmap_async(_flood_unauthorized_axfrs, [(named_port, 5)] * 10)

        # Give the flood a moment to saturate
        time.sleep(1)

        # Try an authorized AXFR from 10.53.0.2 multiple times to increase
        # the chance of hitting the race window where quota is consumed.
        zone = dns.zone.Zone("quota.")
        dns.query.inbound_xfr(
            "10.53.0.3",
            zone,
            port=named_port,
            timeout=10,
            source="10.53.0.2",
        )
