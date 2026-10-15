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

PARENT = "f044.test."
CHILD = f"child.{PARENT}"
QUERY = f"q.{PARENT}"
SERVICE = f"svc.{CHILD}"
FORGED_A = "6.6.6.6"
LEGIT_A = "192.0.2.111"
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
    child = isctest.zone.Zone("child.f044.test.", isctest.template.ANS1, signed=True)
    child.configure(csk=True)

    parent = isctest.zone.Zone("f044.test.", isctest.template.ANS1, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True)

    return {"trust_anchors": parent.trust_anchors()}


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


def _check_rrsig(response, section, owner, rdtype, signer):
    rrsig = _rrset(response, section, owner, dns.rdatatype.RRSIG, covers=rdtype)
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(signer), response.to_text()


def test_resolver_rejects_ancestor_signed_additional_replay():
    # MX includes an A record in the additional section, which is
    # under the zone cut but signed by the parent zone. It is cached as
    # pending.
    response = _query(AUTH, QUERY, "MX")
    isctest.check.noerror(response)
    isctest.check.noadflag(response)
    assert _rrset(response, response.answer, QUERY, dns.rdatatype.MX)
    assert _has_a(response, response.additional, SERVICE, FORGED_A), response.to_text()
    _check_rrsig(response, response.additional, SERVICE, dns.rdatatype.A, PARENT)

    # Check that the child chain validates normally
    response = _query(RESOLVER, CHILD, "SOA")
    isctest.check.noerror(response)
    isctest.check.adflag(response)

    # Fetch the MX again (CD=0). The bad answer should now be omitted.
    response = _query(RESOLVER, QUERY, "MX", cd=True)
    isctest.check.noerror(response)
    isctest.check.noadflag(response)
    isctest.check.rr_count_eq(response.additional, 0)
    assert not _has_a(
        response, response.additional, SERVICE, FORGED_A
    ), response.to_text()

    # Query for the A directly; the parent's answer should now be
    # ejected from the cache and the child's answer used instead.
    response = _query(RESOLVER, SERVICE, "A")
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert not _has_a(response, response.answer, SERVICE, FORGED_A), response.to_text()
    assert _has_a(response, response.answer, SERVICE, LEGIT_A), response.to_text()
    _check_rrsig(response, response.answer, SERVICE, dns.rdatatype.A, CHILD)
