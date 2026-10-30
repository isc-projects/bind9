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
import isctest.mark
import isctest.template
import isctest.zone

PARENT = "f025.test."
CHILD = f"evil.{PARENT}"
CLOSEST = f"victim2.{CHILD}"
ATTACK = f"b.{CLOSEST}"
LEGIT = f"legit.{CHILD}"
FORGED_A = "6.6.6.6"
AUTH = isctest.template.ANS1.ip
RESOLVER = isctest.template.NS2.ip

pytestmark = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/dsset-*",
            "ans*/zones/*.db",
            "ans*/zones/*.db.signed",
        ]
    ),
]


def bootstrap():
    child = isctest.zone.Zone("evil.f025.test.", isctest.template.ANS1, signed=True)
    child.configure(csk=True, sign_params="-3 -")

    parent = isctest.zone.Zone("f025.test.", isctest.template.ANS1, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True, sign_params="-3 -")

    return {"trust_anchors": parent.trust_anchors()}


def _query(server, qname, qtype):
    query = isctest.query.create(qname, qtype)
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


def _has_nsec3_signed_by(response, signer):
    signer_name = dns.name.from_text(signer)
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        rrsig = _rrset(
            response,
            response.authority,
            rrset.name.to_text(),
            dns.rdatatype.RRSIG,
            covers=dns.rdatatype.NSEC3,
        )
        if rrsig is not None and rrsig[0].signer == signer_name:
            return True
    return False


def _check_rrsig(response, section, owner, rdtype, signer, labels=None):
    rrsig = _rrset(response, section, owner, dns.rdatatype.RRSIG, covers=rdtype)
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(signer), response.to_text()
    if labels is not None:
        assert rrsig[0].labels == labels, response.to_text()


def test_forged_response():
    response = _query(AUTH, ATTACK, "A")
    isctest.check.noerror(response)
    assert _has_a(response, response.answer, ATTACK, FORGED_A), response.to_text()
    _check_rrsig(response, response.answer, ATTACK, dns.rdatatype.A, CHILD, labels=3)
    assert _has_nsec3_signed_by(response, PARENT), response.to_text()


def test_resolver_rejects_wrong_zone_nsec3_noqname_proof():
    child_soa = _query(RESOLVER, CHILD, "SOA")
    isctest.check.noerror(child_soa)
    isctest.check.adflag(child_soa)

    # The verified wildcard answer RRSet in the response provides the validator
    # with a (candidate) closest encloser for QNAME. The validator MUST check that
    # the closest encloser is from the correct zone. If this is not the case,
    # as is with this test case, the response must be treated as bogus.
    response = _query(RESOLVER, ATTACK, "A")
    isctest.check.servfail(response)
    isctest.check.noadflag(response)
    assert not _has_a(response, response.answer, ATTACK, FORGED_A), response.to_text()


def test_resolver_accepts_own_zone_nsec3_wildcard_proof():
    # Send query eligble for wildcard expansion (1-label expansion + correct own-zone NSEC3):
    response = _query(RESOLVER, LEGIT, "A")
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert _has_a(response, response.answer, LEGIT, FORGED_A), response.to_text()
    assert _has_nsec3_signed_by(response, CHILD), response.to_text()
