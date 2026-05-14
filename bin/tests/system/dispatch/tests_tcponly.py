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
from re import escape

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
    ]
)


def _count_received(path, qname, protocol):
    pattern = Re(rf"Received {escape(qname)}/IN/A .* \({protocol}\)$")
    with open(path, encoding="utf-8") as fh:
        return sum(1 for line in fh if pattern.search(line.rstrip()))


def test_tcponly_fallback():
    """
    A resolver must fall back to TCP after repeated UDP timeouts to the
    same authoritative server.  ans4 drops every UDP query and answers
    only over TCP; the resolver must reach the answer via the TCP
    fallback path, after at least two UDP attempts have been dropped.
    """
    msg = dns.message.make_query("foo.tcp-only.", "A")
    res = isctest.query.udp(msg, "10.53.0.2", timeout=15)
    isctest.check.noerror(res)
    rdataset = res.find_rrset(
        res.answer,
        dns.name.from_text("foo.tcp-only."),
        dns.rdataclass.IN,
        dns.rdatatype.A,
    )
    assert str(rdataset[0]) == "127.0.0.1"

    udp = _count_received("ans4/ans.run", "foo.tcp-only", "UDP")
    tcp = _count_received("ans4/ans.run", "foo.tcp-only", "TCP")
    assert udp == 2, f"expected exactly 2 UDP queries, got {udp}"
    assert tcp == 1, f"expected exactly 1 TCP query, got {tcp}"
