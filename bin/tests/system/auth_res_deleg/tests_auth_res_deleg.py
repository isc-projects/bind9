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

import os

import isctest
import isctest.mark

pytestmark = [isctest.mark.with_dnstap]


def line_to_query(line):
    # dnstap-read output line example
    # 05-Feb-2026 11:00:57.853 RQ 10.53.0.6:38507 -> 10.53.0.3:22047 TCP 56b fooXXX.example./IN/NS
    _, _, _, _, _, _, _, _, query = line.split(" ", 9)
    return query


def extract_dnstap(ns):
    ns.rndc("dnstap -roll 1")
    path = os.path.join(ns.identifier, "dnstap.out.0")
    dnstapread = isctest.run.cmd(
        [isctest.vars.ALL["DNSTAPREAD"], path],
    )

    lines = dnstapread.out.splitlines()
    return list(map(line_to_query, lines))


def test_auth_res_deleg(ns2):
    msg = isctest.query.create("aaaa.sub.example.", "AAAA")
    res = isctest.query.udp(msg, ns2.ip)
    isctest.check.noerror(res)
    assert len(res.answer[0]) == 1
    res.answer[0].ttl = 300
    assert str(res.answer[0]) == "aaaa.sub.example. 300 IN AAAA ac::dc"

    queries = extract_dnstap(ns2)
    assert len(queries) == 1
    assert queries[0] == "aaaa.sub.example/IN/AAAA"
