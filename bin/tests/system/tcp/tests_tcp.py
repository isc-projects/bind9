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

import socket
import struct
import time

import dns.message
import dns.name
import dns.query
import dns.rrset
import pytest

from isctest.instance import NamedInstance

import isctest

pytestmark = pytest.mark.extra_artifacts(["ans*/ans.run"])

TIMEOUT: int = 10


def create_socket(host: str, port: int) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    return sock


def tcp_round_trip(
    sock: socket.socket, msg: dns.message.Message
) -> dns.message.Message:
    expiration = time.time() + TIMEOUT
    dns.query.send_tcp(sock, msg, expiration)
    response, _ = dns.query.receive_tcp(sock, expiration)
    return response


def test_tcp_garbage(ns7: NamedInstance, named_port: int) -> None:
    with create_socket(ns7.ip, named_port) as sock:
        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=-1, ad=False
        )
        tcp_round_trip(sock, msg)

        # Send DNS message shorter than DNS message header (12),
        # this should cause the connection to be terminated
        sock.send(struct.pack("!H", 11))
        sock.send(struct.pack("!s", b"0123456789a"))

        with pytest.raises(EOFError):
            try:
                tcp_round_trip(sock, msg)
            except ConnectionError as e:
                raise EOFError from e


def test_tcp_garbage_response(ns7: NamedInstance, named_port: int) -> None:
    with create_socket(ns7.ip, named_port) as sock:
        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=-1, ad=False
        )
        tcp_round_trip(sock, msg)

        # Send DNS response instead of DNS query, this should cause
        # the connection to be terminated

        rmsg = dns.message.make_response(msg)

        with pytest.raises(EOFError):
            try:
                tcp_round_trip(sock, rmsg)
            except ConnectionError as e:
                raise EOFError from e


# Regression test for CVE-2022-0396
def test_close_wait(ns7: NamedInstance, named_port: int) -> None:
    with create_socket(ns7.ip, named_port) as sock:
        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=-1, ad=False
        )
        tcp_round_trip(sock, msg)

        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=0, payload=1232, ad=False
        )
        dns.query.send_tcp(sock, msg, time.time() + TIMEOUT)

        # Shutdown the socket, but ignore the other side closing the socket
        # first because we sent DNS message with EDNS0
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except ConnectionError:
            pass
        except OSError:
            pass

    # BIND allows one TCP client, the part above sends DNS messaage with EDNS0
    # after the first query. BIND should react adequately because of
    # ns7/named.dropedns and close the socket, making room for the next
    # request. If it gets stuck in CLOSE_WAIT state, there is no connection
    # available for the query below and it will time out.
    with create_socket(ns7.ip, named_port) as sock:
        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=-1, ad=False
        )
        tcp_round_trip(sock, msg)


# GL #4273
def test_tcp_big(ns7: NamedInstance, named_port: int) -> None:
    with create_socket(ns7.ip, named_port) as sock:
        msg = isctest.query.create(
            dns.name.root, "URI", dnssec=False, use_edns=-1, ad=False, message_id=0
        )
        msg.additional.append(
            dns.rrset.from_text(dns.name.root, 0, 1, "URI", "0 0 " + "b" * 65503)
        )
        tcp_round_trip(sock, msg)

        # Now check that the server is alive and well
        msg = isctest.query.create(
            "a.example.", "A", dnssec=False, use_edns=-1, ad=False
        )
        tcp_round_trip(sock, msg)
