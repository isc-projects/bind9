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

import isctest


def line_to_ips_and_queries(line):
    # dnstap-read output line example
    # 05-Feb-2026 11:00:57.853 RQ 10.53.0.4:38507 -> 10.53.0.3:22047 TCP 56b sub.example.tld/IN/NS
    _, _, _, _, _, dst, _, _, query = line.split(" ", 9)
    ip, _ = dst.split(":", 1)
    return (ip, query)


def extract_dnstap(ns, nsid, expectedlen):
    ns.rndc("dnstap -roll 1")
    path = os.path.join(nsid, "dnstap.out.0")
    dnstapread = isctest.run.cmd(
        [os.getenv("DNSTAPREAD"), path],
    )

    lines = dnstapread.out.splitlines()
    assert expectedlen == len(lines)
    return list(map(line_to_ips_and_queries, lines))


# Because DNSTAP doesn't have ordering guarantee, the order doesn't matter here.
def expect_ip_and_query(expected_ips_and_queries, ips_and_queries):
    found_count = 0
    for expected_ip, expected_query in expected_ips_and_queries:
        found = False
        for ip, query in ips_and_queries:
            if ip == expected_ip and query == expected_query:
                found = True
                found_count += 1
                break
        assert found
    assert found_count == len(expected_ips_and_queries)


def test_selfpointedglue(ns4):
    msg = isctest.query.create("a.sub.example.tld.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.servfail(res)

    ips_and_queries = extract_dnstap(ns4, "ns4", 10)

    # Thanks to the de-duplication, only the first 6 NS IPs are
    # queried (once sub.example.tld. NS is found) instead of 60
    # (60 per NS, with 10 NS).
    expect_ip_and_query(
        [
            ("10.53.0.1", "./IN/NS"),
            ("10.53.0.1", "tld/IN/NS"),
            ("10.53.0.2", "example.tld/IN/NS"),
            ("10.53.0.3", "sub.example.tld/IN/NS"),
            ("10.53.0.3", "a.sub.example.tld/IN/A"),
            ("10.53.0.5", "a.sub.example.tld/IN/A"),
            ("10.53.0.6", "a.sub.example.tld/IN/A"),
            ("10.53.0.7", "a.sub.example.tld/IN/A"),
            ("10.53.0.8", "a.sub.example.tld/IN/A"),
            ("10.53.0.9", "a.sub.example.tld/IN/A"),
        ],
        ips_and_queries,
    )
