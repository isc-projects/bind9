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
import isctest.mark

pytestmark = [isctest.mark.with_dnstap]


def line_to_ips_and_queries(line):
    # dnstap-read output line example
    # 05-Feb-2026 11:00:57.853 RQ 10.53.0.4:38507 -> 10.53.0.3:22047 TCP 56b sub.example.tld/IN/NS
    _, _, _, _, _, dst, _, _, query = line.split(" ", 9)
    ip, _ = dst.split(":", 1)
    return (ip, query)


def extract_dnstap(ns, expectedlen):
    ns.rndc("dnstap -roll 1")
    path = os.path.join(ns.identifier, "dnstap.out.0")
    dnstapread = isctest.run.cmd(
        [isctest.vars.ALL["DNSTAPREAD"], path],
    )

    lines = dnstapread.out.splitlines()
    # Count distinct (destination, query) pairs, not raw lines: under load
    # named may retransmit, adding identical entries.
    ips_and_queries = list(dict.fromkeys(map(line_to_ips_and_queries, lines)))
    assert expectedlen == len(ips_and_queries)
    return ips_and_queries


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


def expect_query(expected_query, expected_query_count, ips_and_queries):
    count = 0
    for _, query in ips_and_queries:
        if query == expected_query:
            count += 1
    assert count == expected_query_count


def test_selfpointedglue1(ns4):
    msg = isctest.query.create("a.sub.example.tld.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.servfail(res)

    # 4 queries to get to the delegation.
    # 13 queries to delegation NS servers (13 distinct destinations).
    ips_and_queries = extract_dnstap(ns4, 17)

    # Thanks to the de-duplication, only the first 13 NS IPs are
    # queried (once sub.example.tld. NS is found) instead of 13*10
    # (13 per NS, with 10 NS).
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
            ("10.53.0.10", "a.sub.example.tld/IN/A"),
            ("10.53.1.1", "a.sub.example.tld/IN/A"),
            ("10.53.1.2", "a.sub.example.tld/IN/A"),
            ("10.53.2.1", "a.sub.example.tld/IN/A"),
            ("127.0.0.1", "a.sub.example.tld/IN/A"),
            ("127.0.0.2", "a.sub.example.tld/IN/A"),
            ("127.0.0.3", "a.sub.example.tld/IN/A"),
        ],
        ips_and_queries,
    )


# This test is useful because the one above hits the max-delegation-servers
# from the first NS name lookup. This one doesn't, because there is only 2
# addresses per NS, but the deduplication avoid the explosion of duplicate
# addresses.
def test_selfpointedglue2(ns4):
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("flush")
        ns4.rndc("reload")
        watcher.wait_for_line("running")
    msg = isctest.query.create("a.sub.example3.tld.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.servfail(res)

    # 4 queries to get to the delegation.
    # 2 queries to delegation NS servers.
    ips_and_queries = extract_dnstap(ns4, 6)

    # Thanks to the de-duplication, only the first 2 NS IPs are
    # queried (once sub.example.tld. NS is found) instead of 2*10
    # (2 per NS with 10 NS).
    expect_ip_and_query(
        [
            ("10.53.0.1", "./IN/NS"),
            ("10.53.0.1", "tld/IN/NS"),
            ("10.53.0.2", "example3.tld/IN/NS"),
            ("10.53.0.3", "sub.example3.tld/IN/NS"),
            ("10.53.0.5", "a.sub.example3.tld/IN/A"),
            ("10.53.0.6", "a.sub.example3.tld/IN/A"),
        ],
        ips_and_queries,
    )


def test_selfpointedglue_nslimit(ns4, templates):
    templates.render(
        "ns4/named.conf", {"maxdelegationservers": "max-delegation-servers 2;"}
    )
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("flush")
        ns4.rndc("reload")
        watcher.wait_for_line("running")

    msg = isctest.query.create("a.sub.example2.tld.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.servfail(res)

    ips_and_queries = extract_dnstap(ns4, 6)

    # Checking the beginning of the resolution
    expect_ip_and_query(
        [
            ("10.53.0.1", "./IN/NS"),
            ("10.53.0.1", "tld/IN/NS"),
            ("10.53.0.2", "example2.tld/IN/NS"),
            ("10.53.0.3", "sub.example2.tld/IN/NS"),
        ],
        ips_and_queries,
    )

    expect_query("a.sub.example2.tld/IN/A", 2, ips_and_queries)
