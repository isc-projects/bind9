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

import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.mark
import isctest.template
import isctest.zone

PARENT = "p22.hack."
CHILD = f"child.{PARENT}"
TRIGGER = f"www.{CHILD}"
PRIME_NX = f"0.{PARENT}"
VICTIM = f"victim.{PARENT}"
AAC = f"aac.{PARENT}"
STUFFED_ENT = f"t.{PARENT}"
STUFFED_RANGE = f"aab.{PARENT}"
CHILD_A = "192.0.2.50"
VICTIM_A = "192.0.2.99"
AAC_A = "192.0.2.77"
AUTH_PARENT = "10.53.0.1"
AUTH_CHILD = "10.53.0.2"
RESOLVER = "10.53.0.3"

pytestmark = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/dsset-*",
            "ans*/zones/*.db",
            "ans*/zones/*.db.signed",
            "ns2/managed-keys.bind.jnl",
            "ns*/zones/*.db",
        ]
    ),
]


def bootstrap():
    child = isctest.zone.Zone(CHILD, isctest.template.NS2)
    child.configure()

    parent = isctest.zone.Zone(PARENT, isctest.template.ANS1, signed=True)
    parent.delegations = [child]
    parent.configure(csk=True)

    return {
        "trust_anchors": parent.trust_anchors(),
        "zones": isctest.template.zones([parent, child]),
    }


def _has_a(response, owner, address):
    rrset = response.get_rrset(
        response.answer, owner, dns.rdataclass.IN, dns.rdatatype.A
    )
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def _has_nsec(response, owner):
    return (
        response.get_rrset(
            response.authority, owner, dns.rdataclass.IN, dns.rdatatype.NSEC
        )
        is not None
    )


def _has_rrsig(response, owner, section, covers):
    return (
        response.get_rrset(
            section, owner, dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=covers
        )
        is not None
    )


def prime_resolver():
    # Caches parent SOA at dns_trust_secure
    # DNSKEY is queried and cached as part of this.
    soa = isctest.query.tcp(isctest.query.create(PARENT, "SOA"), RESOLVER)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Caches real apex parent NSEC at dns_trust_secure
    nx = isctest.query.tcp(isctest.query.create(PRIME_NX, "A"), RESOLVER)
    isctest.check.nxdomain(nx)
    isctest.check.adflag(nx)
    assert _has_nsec(nx, PARENT), nx


def test_malicious_referral():
    referral = isctest.query.tcp(isctest.query.create(TRIGGER, "A"), AUTH_PARENT)
    isctest.check.noerror(referral)
    isctest.check.aaflag(referral)
    assert _has_nsec(referral, CHILD), referral.to_text()
    assert _has_rrsig(referral, CHILD, referral.authority, dns.rdatatype.NSEC)
    assert _has_nsec(referral, STUFFED_ENT), referral.to_text()
    assert _has_nsec(referral, STUFFED_RANGE), referral.to_text()
    assert _has_rrsig(referral, STUFFED_ENT, referral.authority, dns.rdatatype.NSEC)
    assert _has_rrsig(referral, STUFFED_RANGE, referral.authority, dns.rdatatype.NSEC)
    assert not referral.get_rrset(
        referral.answer, TRIGGER, dns.rdataclass.IN, dns.rdatatype.A
    )

    child = isctest.query.tcp(isctest.query.create(TRIGGER, "A"), AUTH_CHILD)
    isctest.check.noerror(child)
    assert _has_a(child, TRIGGER, CHILD_A), child.to_text()


@pytest.mark.parametrize(
    "qname,address",
    [
        (VICTIM, VICTIM_A),
        (AAC, AAC_A),
    ],
    ids=["nodata", "nxdomain"],
)
def test_nsec_piggyback_cache_poisoning(qname, address):
    """
    Reproducer for #5977:
    F-022 NODATA/NXDOMAIN synthesises from piggy-backed NSEC RRs
    """
    # Prime the cache.
    prime_resolver()

    # Trigger the malicious referral.
    trigger = isctest.query.tcp(isctest.query.create(TRIGGER, "A"), RESOLVER)
    isctest.check.noerror(trigger)
    isctest.check.noadflag(trigger)
    assert _has_a(trigger, TRIGGER, CHILD_A), trigger.to_text()

    # Probing query.
    response = isctest.query.tcp(isctest.query.create(qname, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert _has_a(response, qname, address), response.to_text()
    isctest.check.adflag(response)
