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

from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.mark

VICTIM = "victim.example."
ATTACKER = "abc.example."
ATTACK = f"foo.{VICTIM}"
VALID_NXDOMAIN = f"bar.{ATTACKER}"
CONTROL = f"wild1.{VICTIM}"
CONTROL_NODATA = f"wild2.{VICTIM}"
VICTIM_NSEC_OWNER = f"a.{VICTIM}"
ATTACKER_NSEC_OWNER = f"z.{ATTACKER}"
CONTROL_A = "192.0.2.1"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/keys.json",
        ]
    ),
]


def _make_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(),
        algorithm="ECDSAP256SHA256",
        flags=257,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return {
        "private_pem": private_pem,
        "dnskey": dnskey.to_text(),
    }


def bootstrap():
    keys = {zone: _make_key() for zone in [VICTIM, ATTACKER]}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    return {
        "VICTIM_DNSKEY": "".join(keys[VICTIM]["dnskey"].split()[3:]),
        "ATTACKER_DNSKEY": "".join(keys[ATTACKER]["dnskey"].split()[3:]),
    }


def _check_nsec_signer(response, owner, signer):
    text = response.to_text()
    nsec = response.get_rrset(
        response.authority, owner, dns.rdataclass.IN, dns.rdatatype.NSEC
    )
    rrsig = response.get_rrset(
        response.authority,
        owner,
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.NSEC,
    )
    assert nsec and rrsig, text
    assert rrsig[0].signer == dns.name.from_text(signer), text


def test_forged_response_contains_cross_zone_nsec():
    response = isctest.query.tcp(isctest.query.create(ATTACK, "A"), AUTH)
    isctest.check.nxdomain(response)

    _check_nsec_signer(response, ATTACKER_NSEC_OWNER, ATTACKER)
    _check_nsec_signer(response, VICTIM_NSEC_OWNER, VICTIM)


def test_resolver_rejects_cross_zone_nowildcard_proof():
    response = isctest.query.tcp(isctest.query.create(ATTACKER, "SOA"), RESOLVER)
    isctest.check.noerror(response)
    isctest.check.adflag(response)

    response = isctest.query.tcp(isctest.query.create(ATTACK, "A"), RESOLVER)
    isctest.check.servfail(response)
    isctest.check.noadflag(response)


def test_valid_same_zone_nxdomain_still_validates():
    response = isctest.query.tcp(isctest.query.create(VALID_NXDOMAIN, "A"), RESOLVER)
    isctest.check.nxdomain(response)
    isctest.check.adflag(response)


def test_valid_wildcard_still_validates():
    response = isctest.query.tcp(isctest.query.create(CONTROL, "A"), RESOLVER)
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    answer = response.get_rrset(
        response.answer, CONTROL, dns.rdataclass.IN, dns.rdatatype.A
    )
    assert answer, response.to_text()
    assert any(rdata.address == CONTROL_A for rdata in answer), response.to_text()


def test_valid_wildcard_nodata_still_validates():
    response = isctest.query.tcp(isctest.query.create(CONTROL_NODATA, "AAAA"), RESOLVER)
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    assert not response.answer, response.to_text()
