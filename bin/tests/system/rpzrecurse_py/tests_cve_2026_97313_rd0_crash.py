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

import time

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans7/ans.run",
        "ns8/named.args",
    ]
)


def query(ns2, qname, rd):
    message = isctest.query.create(qname, "A", dnssec=False, rd=rd)
    return isctest.query.udp(message, ns2.ip, expected_rcode=None, attempts=1)


def test_rpz_cve_2026_97313_rd0_crash(ns2):
    seed = query(ns2, "trigger.cve-2026-97313.test.", rd=True)
    isctest.check.noerror(seed)
    isctest.check.rdflag(seed)

    # Let the mock server's one-second negative-cache entry expire.
    time.sleep(2)

    trigger = query(ns2, "trigger.cve-2026-97313.test.", rd=False)
    isctest.check.noerror(trigger)
    isctest.check.nordflag(trigger)
