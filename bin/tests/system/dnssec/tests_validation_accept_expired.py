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

from dns import flags

import pytest

import isctest


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns4, templates):
    templates.render("ns4/named.conf", {"accept_expired": True})
    ns4.reconfigure(log=False)


def test_accept_expired(ns4):
    # test TTL of about-to-expire rrsets with accept-expired
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expiring.example", "SOA")
    msg.flags |= flags.CD
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expiring.example", "SOA")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.answer:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.answer:
        assert rrset.ttl <= 120

    # test TTL is capped at RRSIG expiry time in the additional section
    # with accept-expired
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expiring.example", "MX")
    msg.flags |= flags.CD
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expiring.example", "MX")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.additional:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.additional:
        assert rrset.ttl <= 120

    # test TTL of expired rrsets with accept-expired
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expired.example", "SOA")
    msg.flags |= flags.CD
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expired.example", "SOA")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.additional:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.additional:
        assert rrset.ttl <= 120
