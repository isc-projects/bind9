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

from dns.rcode import NOERROR, NXDOMAIN, REFUSED
from dns.rdatatype import CNAME
from pytest import mark, xfail

import isctest


@mark.parametrize(
    "qname, qtype, srcip, rcode",
    [
        ("a.root-servers.nil", "A", "10.53.0.1", NOERROR),
        ("foo.", "A", "10.53.0.1", NXDOMAIN),
        ("foo.", "A", "10.53.0.5", NOERROR),
        ("example.nil", "SOA", "10.53.0.2", REFUSED),
        ("example.nil", "SOA", "10.53.0.3", REFUSED),
        ("example.nil", "SOA", "10.53.0.4", NOERROR),
        ("www.denied.nil", "A", "10.53.0.6", REFUSED),
    ],
)
def test_allow_query_on(ns1, qname, qtype, srcip, rcode):
    msg = isctest.query.create(qname, qtype)
    res = isctest.query.udp(msg, ns1.ip, source=srcip)
    isctest.check.rcode(res, rcode)
    if qname == "example.nil" and rcode == NOERROR:
        assert res.answer
        isctest.check.aaflag(res)
        assert not res.authority


@mark.parametrize("rd", [False, True])
def test_cname_into_refused_dlz(ns1, rd):
    msg = isctest.query.create("dlz.allowed.nil", "A", rd=rd)
    res = isctest.query.udp(msg, ns1.ip, source="10.53.0.2")
    assert [rrset.rdtype for rrset in res.answer] == [CNAME]
    # GL #6412: should be REFUSED. Fix test failure once the bug is fixed.
    isctest.check.noerror(res)
    xfail("bug #6412")
    isctest.check.refused(res)


def test_cname_into_refused_zone(ns1):
    msg = isctest.query.create("denied.allowed.nil", "A")
    res = isctest.query.udp(msg, ns1.ip, source="10.53.0.6")
    assert [rrset.rdtype for rrset in res.answer] == [CNAME]
    # GL #6412: should be REFUSED. Fix test failure once the bug is fixed.
    isctest.check.noerror(res)
    xfail("bug #6412")
    isctest.check.refused(res)
