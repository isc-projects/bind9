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

from re import compile as Re

import dns.message

import isctest


# This test verifies the query pattern when the upstream behaves badly.
# In this scenario, the upstream server (ans3) always responds with a
# BADCOOKIE error for queries within the "example" zone, even on TCP.
# The resolver (ns4), should not resend the same queries over and over
# again, up to the max-query-count threshold. Instead, the expected
# pattern is:
# 1. Priming query, getting the NS for .
# 2. Getting the NS for example.
# 3. Trying to resolve test.example.
# 4. Trying again, but now with the server cookie.
# 5. Trying again, now over TCP.
#
# This means we expect 5 recursion queries trying to resolve test.example.
def test_resend_loop_badcookie(ns4):
    sending_packet = Re("sending packet from 10.53.0.4#[0-9]+ to 10.53.0.3#[0-9]+")
    received_packet = Re("received packet from 10.53.0.3#[0-9]+ to 10.53.0.4#[0-9]+")

    log_sequence = [
        # 1. Priming query, getting the NS for .
        sending_packet,
        Re("COOKIE: [0-9a-z]{16}$"),
        Re(".\\s+IN\\s+NS"),
        # 2. Getting the NS for example.
        sending_packet,
        Re("COOKIE: [0-9a-z]{16}$"),
        Re("example.\\s+IN\\s+NS"),
        # 3. Trying to resolve test.example.
        sending_packet,
        Re("COOKIE: [0-9a-z]{16}$"),
        Re("test.example.\\s+IN\\s+A"),
        # Get the first BADCOOKIE error.
        "UDP response",
        received_packet,
        "BADCOOKIE",
        Re("COOKIE: [0-9a-z]{16}1122334455667788"),
        Re("test.example.\\s+IN\\s+A"),
        # 4. Trying again, but now with the server cookie.
        sending_packet,
        Re("test.example.\\s+IN\\s+A"),
        # Get BADCOOKIE error again.
        "UDP response",
        received_packet,
        "BADCOOKIE",
        Re("COOKIE: [0-9a-z]{16}1122334455667788"),
        Re("test.example.\\s+IN\\s+A"),
        # 5. Trying again, now over TCP.
        sending_packet,
        Re("test.example.\\s+IN\\s+A"),
        # Fails and give up.
        "TCP response",
        received_packet,
        "BADCOOKIE",
        Re("COOKIE: [0-9a-z]{16}1122334455667788"),
        Re("test.example.\\s+IN\\s+A"),
    ]

    msg = dns.message.make_query("test.example", "A")
    with ns4.watch_log_from_here() as watcher:
        res = isctest.query.udp(msg, ns4.ip)
        watcher.wait_for_sequence(log_sequence)

    assert len(ns4.log.grep(sending_packet)) == 5

    isctest.check.servfail(res)

    prohibited_log = "query failed (timed out) for test.example/IN/A"
    assert prohibited_log not in ns4.log


def test_resend_loop_forward(ns1):
    sending_packet = Re("sending packet from 10.53.0.1#[0-9]+ to 10.53.0.3#[0-9]+")
    received_packet = Re("received packet from 10.53.0.3#[0-9]+ to 10.53.0.1#[0-9]+")

    # Make sure the server is done with priming and ./DNSKEY refresh (RFC5011)
    msg = dns.message.make_query(".", "NS")
    isctest.query.udp(msg, ns1.ip)
    query_count_start = len(ns1.log.grep(sending_packet))

    log_sequence = [
        sending_packet,
        "flags: rd; QUESTION: 1",
        received_packet,
        "opcode: QUERY, status: SERVFAIL",
        "flags: qr rd; QUESTION: 1",
        sending_packet,
        "flags: rd cd; QUESTION: 1",
        received_packet,
        "opcode: QUERY, status: SERVFAIL",
        "flags: qr rd; QUESTION: 1",
    ]

    msg = dns.message.make_query("test.com.", "A")
    with ns1.watch_log_from_here() as watcher:
        res = isctest.query.udp(msg, ns1.ip)
        watcher.wait_for_sequence(log_sequence)

    isctest.check.servfail(res)

    query_count_end = len(ns1.log.grep(sending_packet))
    assert query_count_end - query_count_start == 2

    prohibited_log = "query failed (timed out) for test.com/IN/A"
    assert prohibited_log not in ns1.log
