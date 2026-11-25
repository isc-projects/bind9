# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import concurrent.futures

import pytest

import isctest
import isctest.template
import isctest.zone

NAME = "nodata.example."

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/dsset-*",
        "ans*/keys/",
        "ans*/zones/*.db",
        "ans*/zones/*.db.signed",
    ]
)


def bootstrap():
    zone = isctest.zone.Zone("example.", isctest.template.ANS1, signed=True)
    zone.configure(csk=True)
    return {"trust_anchors": zone.trust_anchors()}


def test_late_cd_answer_meets_cached_nodata(ans1, ns2):
    """
    ans1 serves a signed zone in which nodata.example has no A record.  A
    CD=1 client query starts a non-validating fetch on ns2, which ans1
    holds; meanwhile a CD=0 query for the same name gets the validated
    NODATA cached.  ans1 then answers the held fetch with an unsigned
    address, which ns2 must discard in favour of the higher-trust negative
    entry it already holds.
    """
    # Cache the zone's DNSKEY so that the NODATA below is validated, and
    # therefore cached, as soon as it arrives.
    msg = isctest.query.create("example.", "DNSKEY")
    res = isctest.query.udp(msg, ns2.ip)
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        with ans1.watch_log_from_here() as watcher:
            # TCP, so that ns2 going away closes the connection and
            # fails the query at once instead of after the UDP retries.
            msg = isctest.query.create(NAME, "A", cd=True)
            pending = pool.submit(isctest.query.tcp, msg, ns2.ip)
            watcher.wait_for_line(f"Received {NAME.rstrip('.')}/IN/A ")

        msg = isctest.query.create(NAME, "A")
        res = isctest.query.udp(msg, ns2.ip)
        isctest.check.noerror(res)
        isctest.check.adflag(res)
        isctest.check.empty_answer(res)

        msg = isctest.query.create("release._control.", "TXT")
        res = isctest.query.udp(msg, ans1.ip)
        isctest.check.noerror(res)

        res = pending.result()

    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
