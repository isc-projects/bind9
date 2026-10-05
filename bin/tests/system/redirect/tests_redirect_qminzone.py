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

import dns.rcode
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "dig.out.*",
        "ns1/K*",
        "ns1/*.signed",
        "ns1/dsset-nsec3.",
        "ns1/dsset-signed.",
        "ns1/nsec3.db",
        "ns1/signed.db",
        "ns2/example.db",
        "ns2/named.stats",
        "ns2/redirect.db",
        "ns3/K*",
        "ns3/*.signed",
        "ns3/dsset-nsec3.",
        "ns3/dsset-signed.",
        "ns3/nsec3.db",
        "ns3/signed.db",
        "ns4/example.db",
        "ns4/named.stats",
        "ns5/K*",
        "ns5/dsset-*",
        "ns5/*.signed",
        "ns5/root.db",
        "ns5/sign.ns5.*",
        "ns5/signed.db",
        "ns6/signed.db.signed",
        "ns9/K*",
        "ns9/dsset-*",
        "ns9/root.db",
        "ns9/root.db.signed",
        "ns9/sign.ns9.*",
        "ns10/trusted.conf",
        "ns11/trusted.conf",
    ]
)


def bootstrap():
    return {
        "redirect_zone": True,
    }


def check(ns, qtype, dnssec, has_ad, rcode, has_answer):
    msg = isctest.query.create("foo.test.", qtype, dnssec=dnssec)
    response = isctest.query.udp(msg, ns.ip)
    isctest.check.rcode(response, rcode)

    if has_ad:
        isctest.check.adflag(response)
    else:
        isctest.check.noadflag(response)

    if has_answer:
        isctest.check.has_answer(response)
    else:
        isctest.check.empty_answer(response)


@pytest.mark.parametrize(
    "qtype,dnssec,has_ad,rcode,has_answer",
    [
        ("MX", True, True, dns.rcode.NXDOMAIN, False),
        ("MX", False, False, dns.rcode.NOERROR, False),
        ("A", True, True, dns.rcode.NXDOMAIN, False),
        ("A", False, False, dns.rcode.NOERROR, True),
        ("ANY", True, True, dns.rcode.NXDOMAIN, False),
        ("ANY", False, False, dns.rcode.NOERROR, True),
    ],
)
def test_redirect_zone_qmin(ns11, qtype, dnssec, has_ad, rcode, has_answer):
    ns11.rndc("flush")
    # we check for NOERROR and AD=0 for the first query, because the cold-cache
    # response will have no nonexistence proofs, and therefore redirection
    # will be allowed. if NXDOMAIN is expected, we'll only see it on the
    # second response.
    isctest.log.debug("cold cache")
    check(ns11, qtype, dnssec, False, dns.rcode.NOERROR, qtype in ("A", "ANY"))
    isctest.log.debug("warm cache")
    check(ns11, qtype, dnssec, has_ad, rcode, has_answer)
