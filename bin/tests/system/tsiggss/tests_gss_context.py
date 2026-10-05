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
Exercise shared GSS contexts during concurrent queries.
"""

import concurrent.futures
import os
import socket
import struct
import time

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TKEY
import dns.rrset
import dns.tsig
import pytest

import isctest.mark

gssapi = pytest.importorskip("gssapi")
pytestmark = [
    isctest.mark.with_gssapi,
    pytest.mark.extra_artifacts(
        ["ns1/K*", "ns1/_default.tsigkeys", "ns1/example.nil.db"]
    ),
]


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk
        data.extend(chunk)
    return bytes(data)


def establish(ns1, monkeypatch):
    """
    Negotiate using the existing ticket cache, without contacting a KDC.
    """
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{os.getcwd()}/ns1/administrator.ccache")
    context = gssapi.SecurityContext(
        name=gssapi.Name(
            "DNS/blu.example.nil@EXAMPLE.NIL",
            name_type=gssapi.NameType.kerberos_principal,
        ),
        mech=gssapi.MechType.kerberos,
        usage="initiate",
        flags=[
            gssapi.RequirementFlag.mutual_authentication,
            gssapi.RequirementFlag.replay_detection,
            gssapi.RequirementFlag.integrity,
        ],
    )
    token = context.step()
    name = dns.name.from_text(f"context-sharing-{time.time_ns()}.")
    now = int(time.time())
    query = dns.message.make_query(name, "TKEY", "ANY")
    tkey = dns.rdtypes.ANY.TKEY.TKEY(
        dns.rdataclass.ANY,
        dns.rdatatype.TKEY,
        dns.tsig.GSS_TSIG,
        now,
        now + 3600,
        3,
        0,
        token,
    )
    query.additional.append(dns.rrset.from_rdata(name, 0, tkey))
    wire = query.to_wire()
    with socket.create_connection((ns1.ip, ns1.ports.dns), timeout=5) as sock:
        sock.sendall(struct.pack("!H", len(wire)) + wire)
        size = struct.unpack("!H", read_exact(sock, 2))[0]
        response_wire = read_exact(sock, size)
    response = dns.message.from_wire(response_wire, keyring=False)
    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer[0][0].error == 0
    context.step(response.answer[0][0].key)
    assert context.complete
    key = dns.tsig.Key(name, context, dns.tsig.GSS_TSIG)
    keyring = {name: key}
    dns.message.from_wire(response_wire, keyring=keyring)
    return keyring


def signed_query(ns1, keyring):
    query = dns.message.make_query("example.nil.", "SOA")
    query.use_tsig(keyring, algorithm=dns.tsig.GSS_TSIG)
    response = dns.query.tcp(query, ns1.ip, port=ns1.ports.dns, timeout=5)
    assert response.rcode() == dns.rcode.NOERROR
    assert response.had_tsig


def test_concurrent_gss_mic_operations(ns1, monkeypatch):
    keyring = establish(ns1, monkeypatch)

    def exchange(packet):
        wire, query, valid = packet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.sendto(wire, (ns1.ip, ns1.ports.dns))
            response_wire = sock.recv(65535)
        return response_wire, query, valid

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for _ in range(8):
            # Limit outstanding sequence numbers to stay within the GSS
            # replay window even when packets or replies are reordered.
            packets = []
            for _ in range(16):
                query = dns.message.make_query("example.nil.", "SOA")
                query.use_tsig(keyring, algorithm=dns.tsig.GSS_TSIG)
                wire = query.to_wire()
                # Bad MICs exercise the provider's error state; good queries
                # also make named sign replies using the same context.
                bad_mac = query.mac[:-1] + bytes([query.mac[-1] ^ 1])
                assert wire.count(query.mac) == 1
                packets.append((wire.replace(query.mac, bad_mac, 1), query, False))
                packets.append((wire, query, True))

            futures = [pool.submit(exchange, packet) for packet in packets]
            for future in concurrent.futures.as_completed(futures):
                wire, query, valid = future.result()
                # All client GSS calls, including response verification,
                # run on this thread. Workers only exchange raw packets.
                response = dns.message.from_wire(
                    wire, keyring=keyring if valid else False, request_mac=query.mac
                )
                assert response.id == query.id
                assert response.had_tsig
                if valid:
                    assert response.rcode() == dns.rcode.NOERROR
                    assert response.tsig[0].error == 0
                else:
                    assert response.rcode() == dns.rcode.NOTAUTH
                    assert response.tsig[0].error == dns.rcode.BADSIG
    signed_query(ns1, keyring)
