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
import socket
import struct
import time

import dns.exception
import dns.message
import dns.query
import pytest

from isctest.template import ANS1, ANS2, Nameserver

import isctest

TIMEOUT = 3
GARBAGE = b"\x00\x03\x00\x01\x02"  # three bytes of nonsense, framed for TCP


def port() -> int:
    return int(os.environ["PORT"])


def query() -> dns.message.Message:
    return isctest.query.create("bar.example.", "A", dnssec=False, rd=False)


def tcp_exchange(
    server: Nameserver,
    *items: dns.message.Message | bytes,
    reset: bool = False,
    wait: float = TIMEOUT,
) -> tuple[list[dns.message.Message], bool]:
    """
    Send the items over a new TCP connection, messages framed and bytes as
    they are, and return the responses that arrive within `wait` seconds,
    plus whether the server closed the connection.  With `reset`, tear the
    connection down with an RST segment instead of a FIN.
    """
    with socket.create_connection((server.ip, port()), timeout=TIMEOUT) as sock:
        if reset:
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
        for item in items:
            if isinstance(item, bytes):
                sock.sendall(item)
            else:
                dns.query.send_tcp(sock, item)
        sock.setblocking(False)  # as dns.query.receive_tcp() expects
        responses = []
        try:
            while True:
                responses.append(dns.query.receive_tcp(sock, time.time() + wait)[0])
        except dns.exception.Timeout:
            return responses, False
        except EOFError:
            return responses, True


def check_still_answering() -> None:
    for transport in (isctest.query.udp, isctest.query.tcp):
        res = transport(query(), ANS1.ip, timeout=TIMEOUT, attempts=2)
        isctest.check.noerror(res)
        isctest.check.rr_count_eq(res.answer, 1)


def test_server_survives_invalid_udp_query():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(GARBAGE, (ANS1.ip, port()))
    check_still_answering()


def test_invalid_tcp_query_is_dropped_but_the_connection_kept():
    msg = query()
    responses, closed = tcp_exchange(ANS1, GARBAGE, msg)
    assert [res.id for res in responses] == [msg.id]
    assert not closed
    check_still_answering()


@pytest.mark.parametrize("reset", [False, True], ids=["fin", "rst"])
@pytest.mark.parametrize(
    "partial",
    [b"", b"\x00", query().to_wire(prepend_length=True)[:-3]],
    ids=["nothing", "length", "message"],
)
def test_server_survives_early_disconnect(partial, reset):
    tcp_exchange(ANS1, partial, reset=reset, wait=0)
    check_still_answering()


def test_pipelined_tcp_queries_are_all_answered():
    msgs = [query() for _ in range(3)]
    responses, _ = tcp_exchange(ANS1, *msgs)
    assert [res.id for res in responses] == [msg.id for msg in msgs]


def test_ignored_tcp_connection_survives_garbage_collection():
    responses, closed = tcp_exchange(ANS2, query())
    assert not responses
    assert not closed
