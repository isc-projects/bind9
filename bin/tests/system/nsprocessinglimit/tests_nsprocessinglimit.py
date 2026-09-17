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
    assert expectedlen == len(lines)
    return map(line_to_ips_and_queries, lines)


def expect_query(expected_query, expected_query_count, ips_and_queries):
    count = 0
    for _, query in ips_and_queries:
        if query == expected_query:
            count += 1
    assert count == expected_query_count


def expect_next_ip_and_query(expected_ips_and_queries, ips_and_queries):
    for expected_ip, expected_query in expected_ips_and_queries:
        ip, query = next(ips_and_queries)
        assert ip == expected_ip
        assert query == expected_query


def check_nsprocessinglimit(ns, queries_count):
    msg = isctest.query.create("a.sub.example.tld.", "A")
    res = isctest.query.tcp(msg, ns.ip)
    isctest.check.servfail(res)

    # The 4 formers lines are request to find sub.example.tld NSs.
    # The latest are queries to sub.example.tld NSs.
    ips_and_queries = extract_dnstap(ns, queries_count)

    # Checking the begining of the resulution
    expect_next_ip_and_query(
        [
            ("10.53.0.1", "./IN/NS"),
            ("10.53.0.1", "tld/IN/NS"),
            ("10.53.0.2", "example.tld/IN/NS"),
            ("10.53.0.3", "sub.example.tld/IN/NS"),
        ],
        ips_and_queries,
    )
    expect_query("a.sub.example.tld/IN/A", queries_count - 4, ips_and_queries)


def test_nsprocessinglimit_default(ns4):
    check_nsprocessinglimit(ns4, 17)


def reconfig_maxdelegationservers(ns, templates, count):
    templates.render(
        "ns4/named.conf", {"maxdelegationservers": f"max-delegation-servers {count};"}
    )
    with ns.watch_log_from_here() as watcher:
        ns.rndc("flush")
        ns.rndc("reload")
        watcher.wait_for_line("running")


def reconfig_maxdelegationservers_failure(ns, templates, count):
    templates.render(
        "ns4/named.conf", {"maxdelegationservers": f"max-delegation-servers {count};"}
    )
    with ns.watch_log_from_here() as watcher:
        # Reload will fail, so do not raise the exception so the config line
        # can be checked.
        ns.rndc("reload", raise_on_exception=False)
        watcher.wait_for_line("reloading configuration failed: out of range")


def test_nsprocessinglimit_13ns(ns4, templates):
    reconfig_maxdelegationservers(ns4, templates, 13)
    check_nsprocessinglimit(ns4, 17)


def test_nsprocessinglimit_5ns(ns4, templates):
    reconfig_maxdelegationservers(ns4, templates, 5)
    check_nsprocessinglimit(ns4, 9)


def test_nsprocessinglimit_20ns(ns4, templates):
    reconfig_maxdelegationservers(ns4, templates, 20)
    check_nsprocessinglimit(ns4, 24)


def test_nsprocessinglimit_lower(ns4, templates):
    reconfig_maxdelegationservers_failure(ns4, templates, 0)


def test_nsprocessinglimit_upper(ns4, templates):
    reconfig_maxdelegationservers_failure(ns4, templates, 101)
