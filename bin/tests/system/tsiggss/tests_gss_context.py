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
Exercise GSS-TSIG sessions across view teardown and server restart.
"""

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
    isctest.mark.with_fips_dh,
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


def test_gss_context_survives_reload(ns1, monkeypatch):
    keyring = establish(ns1, monkeypatch)
    signed_query(ns1, keyring)
    for _ in range(3):
        ns1.reload()
        # Old views release asynchronous references after reload returns.
        # Keep querying through that interval with the original session.
        for _ in range(10):
            time.sleep(0.1)
            signed_query(ns1, keyring)


def test_gss_context_survives_restart(ns1, monkeypatch):
    keyring = establish(ns1, monkeypatch)
    signed_query(ns1, keyring)
    ns1.stop(["--use-rndc", "--port", str(ns1.ports.rndc)])
    ns1.start(["--noclean", "--restart", "--port", str(ns1.ports.dns)])
    # The client keeps its original context: no new TKEY negotiation.
    signed_query(ns1, keyring)
