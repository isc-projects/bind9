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

F055_ZONE = "f055.test."
SAFE = f"safe.{F055_ZONE}"
CUT = f"cut.{F055_ZONE}"
CONTROL = f"ctl.{F055_ZONE}"
ATTACK = f"a.{CUT}"
CONTROL_ATTACK = f"a.{CONTROL}"
SAFE_A = "198.51.100.55"
FORGED_A = "192.0.2.55"
AUTH = isctest.template.ANS3.ip
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
    zone = isctest.zone.Zone("f055.test.", isctest.template.ANS3, signed=True)
    zone.configure(csk=True, sign_params="-3 -")

    return {"trust_anchors": zone.trust_anchors()}


def _query(server, qname, qtype):
    query = isctest.query.create(qname, qtype)
    return isctest.query.tcp(query, server)


def _rrset(response, section, owner, rdtype, covers=None):
    if covers is None:
        return response.get_rrset(
            section,
            dns.name.from_text(owner),
            dns.rdataclass.IN,
            rdtype,
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


def _has_forged_optout_nsec3(response):
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        if rrset[0].flags == 1:
            rrsig = _rrset(
                response,
                response.authority,
                rrset.name.to_text(),
                dns.rdatatype.RRSIG,
                covers=dns.rdatatype.NSEC3,
            )
            return rrsig is not None and rrsig[0].signer == dns.name.from_text(
                F055_ZONE
            )
    return False


def test_forged_bogus_inner_nsec3():
    cut_ds = _query(AUTH, CUT, "DS")
    isctest.check.noerror(cut_ds)
    assert _has_forged_optout_nsec3(cut_ds), cut_ds.to_text()


def test_resolver_rejects_bogus_inner_nsec3_downgrade():
    # Baseline (proves the trust anchor and NSEC3 chain validate)
    response = _query(RESOLVER, SAFE, "A")
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert _has_a(response, response.answer, SAFE, SAFE_A)

    # Control (identical DS NODATA without the forged NSEC3)
    response = _query(RESOLVER, CONTROL_ATTACK, "A")
    isctest.check.servfail(response)
    isctest.check.noadflag(response)
    assert not _has_a(response, response.answer, CONTROL_ATTACK, FORGED_A)

    # Attack (DS NODATA carries the forged Opt-Out NSEC3)
    response = _query(RESOLVER, ATTACK, "A")
    isctest.check.servfail(response)
    isctest.check.noadflag(response)
    assert not _has_a(response, response.answer, ATTACK, FORGED_A)
