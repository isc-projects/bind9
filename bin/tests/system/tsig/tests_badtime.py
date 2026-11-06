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

import socket
import time

import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TSIG
import dns.rrset
import dns.tsig
import dns.tsigkeyring
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns1/named-fips.conf",
    ]
)

TIMEOUT = 10


def create_msg(qname, qtype, edns=-1):
    msg = dns.message.make_query(qname, qtype, use_edns=edns)
    return msg


def timeout():
    return time.time() + TIMEOUT


def create_socket(host, port):
    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    return sock


def test_tsig_badtime(named_port):
    with create_socket("10.53.0.1", named_port) as sock:
        msg = create_msg("a.example.", "A")

        keyring = dns.tsigkeyring.from_text(
            {
                "sha256": "R16NojROxtxH/xbDl//ehDsHm5DjWTQ2YXV+hGC2iBY=",
            }
        )

        msg.use_tsig(keyring, keyname="sha256", fudge=0)

        wire = msg.to_wire()
        assert len(wire) > 0

        time.sleep(3)

        dns.query.send_tcp(sock, wire, timeout())
        with pytest.raises(dns.tsig.PeerBadTime):
            dns.query.receive_tcp(sock, timeout(), keyring=keyring)


def test_tsig_empty_mac_in_request(ns1):
    # An empty MAC is acceptable in a response carrying BADSIG, never in a
    # request (CVE-2020-8617).
    msg = dns.message.make_query("isc.org.", "A", use_edns=False, flags=0)
    msg.keyring = False  # the BADSIG reply is unsigned
    tsig = dns.rdtypes.ANY.TSIG.TSIG(
        dns.rdataclass.ANY,
        dns.rdatatype.TSIG,
        dns.tsig.HMAC_SHA256,
        time_signed=0,
        fudge=300,
        mac=b"",
        original_id=0,
        error=dns.rcode.BADSIG,
        other=b"",
    )
    msg.additional.append(dns.rrset.from_rdata("sha256.", 0, tsig))

    res = isctest.query.tcp(msg, ns1.ip)
    isctest.check.notauth(res)
    assert res.tsig[0].error == dns.rcode.BADSIG
