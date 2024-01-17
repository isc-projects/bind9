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

import pytest

pytest.importorskip("dns", minversion="2.5.0")

import dns.message

import isctest
import isctest.mark


pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/example*.db",
    ]
)


@pytest.mark.requires_zones_loaded("ns1", "ns2", "ns3", "ns4", "ns5")
@pytest.mark.parametrize(
    "qname,ns,rcode",
    [
        ("example.", 2, dns.rcode.NOERROR),
        ("example.", 3, dns.rcode.NOERROR),
        ("example.", 4, dns.rcode.NOERROR),
        ("example-aes-128.", 2, dns.rcode.NOERROR),
        ("example-aes-256.", 3, dns.rcode.NOERROR),
        pytest.param(
            "example-chacha-20.",
            4,
            dns.rcode.NOERROR,
            marks=isctest.mark.without_fips,
        ),
        ("example-aes-256", 2, dns.rcode.SERVFAIL),
        pytest.param(
            "example-chacha-20",
            2,
            dns.rcode.SERVFAIL,
            marks=isctest.mark.without_fips,
        ),
        ("example-aes-128", 3, dns.rcode.SERVFAIL),
        pytest.param(
            "example-chacha-20",
            3,
            dns.rcode.SERVFAIL,
            marks=isctest.mark.without_fips,
        ),
        ("example-aes-128", 4, dns.rcode.SERVFAIL),
        ("example-aes-256", 4, dns.rcode.SERVFAIL),
        # NS5 tries to download the zone over TLSv1.2
        ("example", 5, dns.rcode.SERVFAIL),
        ("example-aes-128", 5, dns.rcode.SERVFAIL),
        ("example-aes-256", 5, dns.rcode.SERVFAIL),
        pytest.param(
            "example-chacha-20",
            5,
            dns.rcode.SERVFAIL,
            marks=isctest.mark.without_fips,
        ),
    ],
)
def test_cipher_suites_tls_xfer(qname, ns, rcode):
    msg = dns.message.make_query(qname, "AXFR")
    ans = isctest.query.tls(msg, f"10.53.0.{ns}")
    assert ans.rcode() == rcode
    if rcode == dns.rcode.NOERROR:
        assert ans.answer != []
    elif rcode == dns.rcode.SERVFAIL:
        assert ans.answer == []
