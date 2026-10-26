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

ARTIFACTS = pytest.mark.extra_artifacts(
    [
        "ans*/dsset-*",
        "ans*/zones/*.db",
        "ans*/zones/*.db.signed",
        "ns3/dsset-*",
        "ns3/zones/*.db",
        "ns3/zones/*.db.signed",
    ]
)

SIGNED_ZONE_MARKS = [isctest.mark.with_ecdsa_deterministic, ARTIFACTS]

F004_ZONE = "f004.test."
F004_VICTIM = f"victim.{F004_ZONE}"
F004_VICTIM_A = "203.0.113.1"


def f004_bootstrap():
    zone = isctest.zone.Zone(F004_ZONE, isctest.template.ANS1, signed=True)
    zone.configure(csk=True)
    return {"trust_anchors": zone.trust_anchors()}


def has_a(response, owner, address):
    rrset = response.get_rrset(
        response.answer, owner, dns.rdataclass.IN, dns.rdatatype.A
    )
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def get_nsec(response, section, owner):
    return response.get_rrset(section, owner, dns.rdataclass.IN, dns.rdatatype.NSEC)


def check_nsec(response, section, owner, next_name, signer):
    text = response.to_text()
    nsec = get_nsec(response, section, owner)
    rrsig = response.get_rrset(
        section,
        owner,
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.NSEC,
    )
    assert nsec and rrsig, text
    assert nsec[0].next == dns.name.from_text(next_name), text
    assert rrsig[0].signer == dns.name.from_text(signer), text
    return rrsig


def check_forged_nsec(response, section, owner, next_name, zone, key_tag):
    rrsig = check_nsec(response, section, owner, next_name, zone)
    assert rrsig[0].key_tag == key_tag, response.to_text()
