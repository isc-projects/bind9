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

import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.template
import isctest.zone

VICTIM = "victim.example."
ATTACKER = "abc.example."
ATTACK = f"foo.{VICTIM}"
VALID_NXDOMAIN = f"bar.{ATTACKER}"
CONTROL = f"wild1.{VICTIM}"
CONTROL_NODATA = f"wild2.{VICTIM}"
CONTROL_A = "192.0.2.1"

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/dsset-*",
        "ans*/zones/*.db",
        "ans*/zones/*.db.signed",
    ]
)


def bootstrap():
    trust_anchors = []
    for name in (VICTIM, ATTACKER):
        zone = isctest.zone.Zone(name, isctest.template.ANS1, signed=True)
        zone.configure(csk=True)
        trust_anchors += zone.trust_anchors()
    return {"trust_anchors": trust_anchors}


@pytest.fixture(autouse=True)
def autouse_flush_resolver_cache(ns2):
    ns2.rndc("flush")


@pytest.mark.asyncserver_test
def test_forged_response_contains_cross_zone_nsec(ans1):
    response = isctest.query.tcp(isctest.query.create(ATTACK, "A"), ans1.ip)
    isctest.check.nxdomain(response)

    signers = {
        rrsig[0].signer
        for rrsig in response.authority
        if rrsig.rdtype == dns.rdatatype.RRSIG and rrsig.covers == dns.rdatatype.NSEC
    }
    assert signers == {
        dns.name.from_text(VICTIM),
        dns.name.from_text(ATTACKER),
    }, response.to_text()


def test_resolver_rejects_cross_zone_nowildcard_proof(ns2):
    response = isctest.query.tcp(isctest.query.create(ATTACKER, "SOA"), ns2.ip)
    isctest.check.noerror(response)
    isctest.check.adflag(response)

    response = isctest.query.tcp(isctest.query.create(ATTACK, "A"), ns2.ip)
    isctest.check.servfail(response)
    isctest.check.noadflag(response)


def test_valid_same_zone_nxdomain_still_validates(ns2):
    response = isctest.query.tcp(isctest.query.create(VALID_NXDOMAIN, "A"), ns2.ip)
    isctest.check.nxdomain(response)
    isctest.check.adflag(response)


def test_valid_wildcard_still_validates(ns2):
    response = isctest.query.tcp(isctest.query.create(CONTROL, "A"), ns2.ip)
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    answer = response.get_rrset(
        response.answer, CONTROL, dns.rdataclass.IN, dns.rdatatype.A
    )
    assert answer, response.to_text()
    assert any(rdata.address == CONTROL_A for rdata in answer), response.to_text()


def test_valid_wildcard_nodata_still_validates(ns2):
    response = isctest.query.tcp(isctest.query.create(CONTROL_NODATA, "AAAA"), ns2.ip)
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert not response.answer, response.to_text()
