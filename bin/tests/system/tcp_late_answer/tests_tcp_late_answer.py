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

"""
A late answer on a shared outgoing TCP connection.

ns2 forwards everything to ans1, which answers only over TCP, so the
TCP queries of all ns2's fetches are pipelined on the one connection
ns2 keeps to ans1.  When the answer to a query that ns2 has already
given up on (timed out or cancelled) arrives on that connection, the
connection must survive: the other queries in flight on it must be
answered without being resent.

The client queries are sent pipelined on one TCP connection to ns2, so
that all the fetches run on the same event loop and share the one
outgoing connection.
"""

from collections import defaultdict
from re import compile as Re
from re import escape

import socket
import time

import dns.query

import isctest

TEARDOWN = Re(r"shutting down due to TCP receive error: .*: unexpected error")


def tcp_query(qname):
    """
    The line ans1 logs when it reads a TCP query for `qname`.
    """
    return Re(rf"Received {escape(qname)}/IN/A .* \(TCP\)$")


def send(sock, qname):
    msg = isctest.query.create(qname, "A")
    dns.query.send_tcp(sock, msg, time.time() + 10)


def receive(sock, count):
    """
    Read `count` answers and return them by query name.
    """
    answers = defaultdict(list)
    for _ in range(count):
        res, _ = dns.query.receive_tcp(sock, time.time() + 10)
        answers[res.question[0].name.to_text()].append(res)
    return answers


def test_late_answer_for_swept_query(ns2, ans1, named_port):
    """
    Three fetches pipelined on the connection; the first one's answer is
    delayed past the second one's per-query timeout.  The read that
    delivers the first answer times the second query out ("sweeps" it)
    and the second answer, read right behind the first, is then one ns2
    is no longer waiting for.  The third query must still be answered
    on the same connection.
    """
    teardowns = len(ns2.log.grep(TEARDOWN))

    with socket.create_connection((ns2.ip, named_port), timeout=10) as sock:
        # ns2 gives up on a TCP query to ans1 after ans1's RTT (close to
        # zero here) plus 1.2 s: 1 s allowed for TCP connection setup and
        # a 200 ms margin, constants in fctx_query() and
        # fctx_setretryinterval().  Each new query restarts the
        # connection's read timer with its own timeout.  In seconds from
        # when ans1 reads late.test:
        #
        #   0.0  ans1 reads late.test and holds its answer until 1.8
        #   0.1  swept.test queues behind it; ns2 gives up on it at 1.3
        #   1.0  victim.test restarts the read timer, now due at 2.2
        #   1.8  the late answer arrives; reading it, ns2 times out
        #        swept.test, whose answer comes right after
        with ans1.watch_log_from_here() as watcher:
            send(sock, "late.test.")
            watcher.wait_for_line(tcp_query("late.test"))
        send(sock, "swept.test.")
        time.sleep(0.9)
        send(sock, "victim.test.")
        answers = receive(sock, 3)

    for qname in ["late.test.", "swept.test.", "victim.test."]:
        isctest.check.noerror(answers[qname][0])

    assert len(ns2.log.grep(TEARDOWN)) == teardowns
    assert len(ans1.log.grep(tcp_query("victim.test"))) == 1


def test_late_answer_for_canceled_query(ns2, ans1, named_port):
    """
    One fetch in flight, then enough clients for the same other name to
    exceed the recursive-clients soft limit, which aborts the oldest
    recursing client and cancels its fetch while its TCP query is still
    pending.  The answer to that query then arrives; the other fetch's
    query must still be answered on the same connection.
    """
    teardowns = len(ns2.log.grep(TEARDOWN))

    with socket.create_connection((ns2.ip, named_port), timeout=10) as sock:
        with ans1.watch_log_from_here() as watcher:
            send(sock, "canceled.test.")
            watcher.wait_for_line(tcp_query("canceled.test"))
        for _ in range(9):
            send(sock, "sibling.test.")
        answers = receive(sock, 10)

    # The aborted client gets SERVFAIL.
    isctest.check.servfail(answers["canceled.test."][0])
    for res in answers["sibling.test."]:
        isctest.check.noerror(res)

    assert len(ns2.log.grep(TEARDOWN)) == teardowns
    assert len(ans1.log.grep(tcp_query("sibling.test"))) == 1
