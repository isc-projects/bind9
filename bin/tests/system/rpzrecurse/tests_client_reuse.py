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

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "dnsrps.cache",
        "dnsrps.conf",
        "ans*/ans.run",
        "ns2/*.queries",
        "ns2/*.local",
        "ns2/named.*.conf",
        "ns2/named.conf.header",
        "ns8/named.args",
    ]
)


def query(ns8, qname, rd):
    message = isctest.query.create(qname, "A", dnssec=False, rd=rd)
    return isctest.query.udp(message, ns8.ip, expected_rcode=None, attempts=1)


def test_rpz_recursion_eligibility_after_udp_client_reuse(ns8):
    seed = query(ns8, "seed.client-reuse.", rd=False)
    isctest.check.noerror(seed)
    isctest.check.empty_answer(seed)
    isctest.check.nordflag(seed)

    answer = query(ns8, "blocked.client-reuse.", rd=True)
    isctest.check.nxdomain(answer)
    isctest.check.empty_answer(answer)
    isctest.check.rdflag(answer)
