#!/usr/bin/python3

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

# pylint: disable=unused-variable

import socket
import struct
import time

import pytest

TIMEOUT = 10


def create_msg(qname, qtype):
    import dns.message
    msg = dns.message.make_query(qname, qtype, want_dnssec=True,
                                 use_edns=0, payload=4096)
    return msg


def timeout():
    return time.time() + TIMEOUT


def create_socket(host, port):
    sock = socket.create_connection((host, port), timeout=1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    return sock


@pytest.mark.dnspython
@pytest.mark.dnspython2
def test_tcp_garbage(port):
    import dns.query

    with create_socket("10.53.0.7", port) as sock:

        msg = create_msg("a.example.", "A")
        (sbytes, stime) = dns.query.send_tcp(sock, msg, timeout())
        (response, rtime) = dns.query.receive_tcp(sock, timeout())

        wire = msg.to_wire()
        assert len(wire) > 0

        # Send DNS message shorter than DNS message header (12),
        # this should cause the connection to be terminated
        sock.send(struct.pack('!H', 11))
        sock.send(struct.pack('!s', b'0123456789a'))

        with pytest.raises(EOFError):
            try:
                (sbytes, stime) = dns.query.send_tcp(sock, msg, timeout())
                (response, rtime) = dns.query.receive_tcp(sock, timeout())
            except ConnectionError as e:
                raise EOFError from e


@pytest.mark.dnspython
@pytest.mark.dnspython2
def test_tcp_garbage_response(port):
    import dns.query
    import dns.message

    with create_socket("10.53.0.7", port) as sock:

        msg = create_msg("a.example.", "A")
        (sbytes, stime) = dns.query.send_tcp(sock, msg, timeout())
        (response, rtime) = dns.query.receive_tcp(sock, timeout())

        wire = msg.to_wire()
        assert len(wire) > 0

        # Send DNS response instead of DNS query, this should cause
        # the connection to be terminated

        rmsg = dns.message.make_response(msg)
        (sbytes, stime) = dns.query.send_tcp(sock, rmsg, timeout())

        with pytest.raises(EOFError):
            try:
                (response, rtime) = dns.query.receive_tcp(sock, timeout())
            except ConnectionError as e:
                raise EOFError from e
