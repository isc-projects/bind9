#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.template
import isctest.zone

TESTZONE = "f043.test."
QUERY = f"svc.{TESTZONE}"
VICTIM = f"victim.{TESTZONE}"
FORGED_A = "198.51.100.45"
LEGIT_A = "192.0.2.113"
AUTH = isctest.template.ANS1.ip
RESOLVER = isctest.template.NS2.ip

pytestmark = [
    pytest.mark.extra_artifacts(
        [
            "ans*/ans.run",
            "ans*/dsset-*",
            "ans*/keys/",
            "ans*/zones/*.db",
            "ans*/zones/*.db.signed",
        ]
    ),
]


def bootstrap():
    zone = isctest.zone.Zone("f043.test.", isctest.template.ANS1, signed=True)
    zone.configure(csk=True)

    return {"trust_anchors": zone.trust_anchors()}


def _query(server, qname, qtype, cd=False):
    query = isctest.query.create(qname, qtype, cd=cd)
    return isctest.query.tcp(query, server)


def _rrset(response, section, owner, rdtype, covers=None):
    if covers is None:
        return response.get_rrset(
            section, dns.name.from_text(owner), dns.rdataclass.IN, rdtype
        )
    return response.get_rrset(
        section,
        dns.name.from_text(owner),
        dns.rdataclass.IN,
        rdtype,
        covers=covers,
    )


def _has_a(response, section, owner, address):
    rrset = _rrset(response, section, owner, dns.rdatatype.A)
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def _check_rrsig(response, section, owner, rdtype, signer, labels=None):
    rrsig = _rrset(response, section, owner, dns.rdatatype.RRSIG, covers=rdtype)
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(signer), response.to_text()
    if labels is not None:
        assert rrsig[0].labels == labels, response.to_text()


def test_direct_fromwildcard_additional_fixture():
    carrier = _query(AUTH, QUERY, "MX")
    isctest.check.noerror(carrier)
    assert _rrset(carrier, carrier.answer, QUERY, dns.rdatatype.MX)
    assert _has_a(carrier, carrier.additional, VICTIM, FORGED_A), carrier.to_text()
    _check_rrsig(
        carrier,
        carrier.additional,
        VICTIM,
        dns.rdatatype.A,
        TESTZONE,
        labels=2,
    )


def test_resolver_rejects_fromwildcard_additional_replay():
    soa = _query(RESOLVER, TESTZONE, "SOA")
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    carrier = _query(RESOLVER, QUERY, "MX", cd=True)
    isctest.check.noerror(carrier)

    response = _query(RESOLVER, VICTIM, "A")
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert not _has_a(response, response.answer, VICTIM, FORGED_A), response.to_text()
    assert _has_a(response, response.answer, VICTIM, LEGIT_A), response.to_text()
    _check_rrsig(response, response.answer, VICTIM, dns.rdatatype.A, TESTZONE)
