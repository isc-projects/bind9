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
    assert expectedlen == len(lines)
    return list(map(line_to_ips_and_queries, lines))


# Because DNSTAP doesn't have ordering guarantee, the order doesn't matter here.
def has_ip_and_query(expected_ips_and_queries, ips_and_queries):
    found_count = 0
    for expected_ip, expected_query in expected_ips_and_queries:
        for ip, query in ips_and_queries:
            if ip == expected_ip and query == expected_query:
                found_count += 1
                break
    return found_count == len(expected_ips_and_queries)


# Test the max-delegation-servers limit on flow where ADB attempt
# a lookup from an NS name rather than directly with the NS addresses.
def test_nslimit_outdomain(ns4, templates):
    templates.render(
        "ns4/named.conf", {"maxdelegationservers": "max-delegation-servers 2;"}
    )
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("flush")
        ns4.rndc("reload")
        watcher.wait_for_line("running")

    msg = isctest.query.create("sub.example4.tld.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.servfail(res)

    ips_and_queries = extract_dnstap(ns4, 9)

    # The resolver first resolve example4.tld. and gets the NS for sub.example.tld.
    # which is out-domain. So it resolves it.
    assert has_ip_and_query(
        [
            ("10.53.0.1", "./IN/NS"),
            ("10.53.0.1", "tld/IN/NS"),
            ("10.53.0.2", "example4.tld/IN/NS"),
            ("10.53.0.3", "sub.example4.tld/IN/A"),
            ("10.53.0.2", "dnshoster.tld/IN/NS"),
        ],
        ips_and_queries,
    )

    # Then, because max-delegation-servers is 2, the resolver will try to use either
    # the NS ns1.dnshoster.tld or the NS ns2.dnshoster.tld. or the NS ns3.dnshoster.tld.
    #
    # What is important here, is that the NS of sub.example4.tld are _names_, so
    # this is going through the dns_adb_createfind() flow, and it does stop after 2
    # queries (on the two IPs of one of the NS server above) and _won't_ try another
    # NS name (becuse max-delegation-servers will be reached).
    #
    # Note that the sum of all the queries checked here is 8 and not 9. This is because
    # when dnshoster.tld has been resolved, the resolver resolved 2 names. But the IPs
    # of only one of the two names has been used. (This is checked below).

    used_ns1 = has_ip_and_query(
        [
            ("10.53.0.2", "ns1.dnshoster.tld/IN/A"),
            ("10.53.0.5", "sub.example4.tld/IN/A"),
            ("10.53.0.6", "sub.example4.tld/IN/A"),
        ],
        ips_and_queries,
    )

    used_ns2 = has_ip_and_query(
        [
            ("10.53.0.2", "ns2.dnshoster.tld/IN/A"),
            ("10.53.1.1", "sub.example4.tld/IN/A"),
            ("10.53.1.2", "sub.example4.tld/IN/A"),
        ],
        ips_and_queries,
    )

    used_ns3 = has_ip_and_query(
        [
            ("10.53.0.2", "ns3.dnshoster.tld/IN/A"),
            ("10.53.2.1", "sub.example4.tld/IN/A"),
            ("10.53.2.2", "sub.example4.tld/IN/A"),
        ],
        ips_and_queries,
    )

    assert used_ns1 or used_ns2 or used_ns3
