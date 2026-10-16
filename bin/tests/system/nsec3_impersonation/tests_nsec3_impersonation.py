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

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

from isctest.template import TrustAnchor

import isctest
import isctest.mark
import isctest.template
import isctest.zone

APEX_HASH = dns.dnssec.nsec3_hash("tld.test.", None, 0, 1)
ATTACKER = f"{APEX_HASH.lower()}.tld.test."
VICTIM = "victim.tld.test."
AUTH = isctest.template.ANS1.ip
RESOLVER = isctest.template.NS2.ip

pytestmark = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/dsset-*",
        ]
    ),
]


def bootstrap():
    parent_origin = "tld.test"
    parent_nsec3_hash = dns.dnssec.nsec3_hash(parent_origin, None, 0, 1)

    child_origin = f"{parent_nsec3_hash}.{parent_origin}"

    child = isctest.zone.Zone(child_origin, isctest.template.ANS1, signed=True)
    child.configure(csk=True)

    parent = isctest.zone.Zone(parent_origin, isctest.template.ANS1, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True, sign_params="-3 -")

    return {"trust_anchors": parent.trust_anchors()}


def check_dnskey_response(zone):
    query = isctest.query.create(zone, "DNSKEY")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.noerror(response)
    isctest.check.aaflag(response)
    assert (
        response.get_rrset(
            response.answer,
            dns.name.from_text(zone),
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
        )
        is not None
    ), response


def check_ds_response(zone):
    query = isctest.query.create(zone, "DS")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.noerror(response)
    isctest.check.aaflag(response)
    assert (
        response.get_rrset(
            response.answer,
            dns.name.from_text(zone),
            dns.rdataclass.IN,
            dns.rdatatype.DS,
        )
        is not None
    ), response


def test_attack_responses():
    check_dnskey_response("tld.test.")
    check_dnskey_response(ATTACKER)
    check_ds_response(ATTACKER)

    query = isctest.query.create(VICTIM, "A")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.nxdomain(response)
    isctest.check.aaflag(response)

    nsec3_owner = dns.name.from_text(f"{APEX_HASH}.tld.test.")
    nsec3 = response.get_rrset(
        response.authority,
        nsec3_owner,
        dns.rdataclass.IN,
        dns.rdatatype.NSEC3,
    )
    rrsig = response.get_rrset(
        response.authority,
        nsec3_owner,
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.NSEC3,
    )

    assert nsec3 is not None, response
    assert rrsig is not None, response
    assert rrsig[0].signer == dns.name.from_text(ATTACKER)


def test_nsec3_impersonation():
    """
    Reproducer for #5874:
    F-006 DNSSEC Validation Bypass NSEC3 Apex Hash Label Parent Impersonation
    """
    query = isctest.query.create(VICTIM, "A")
    response = isctest.query.tcp(query, RESOLVER)

    isctest.check.noadflag(response)
    isctest.check.servfail(response)
