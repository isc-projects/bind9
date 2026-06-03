#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import dns.dnssec
import dns.flags
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest

APEX_HASH = "1B40241KFORIOG780N4IKSCRLVETPCTQ"
ATTACKER = f"{APEX_HASH.lower()}.tld.test."
VICTIM = "victim.tld.test."
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "keys.json",
    ]
)


def _make_key(zone):
    private_key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(),
        algorithm="ECDSAP256SHA256",
        flags=257,
    )
    ds = dns.dnssec.make_ds(dns.name.from_text(zone), dnskey, "SHA256")
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return {
        "private_pem": private_pem,
        "dnskey": dnskey.to_text(),
        "ds": ds.to_text(),
    }


def bootstrap():
    zones = ["tld.test.", ATTACKER]
    keys = {zone: _make_key(zone) for zone in zones}

    Path("keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")

    tld_dnskey = "".join(keys["tld.test."]["dnskey"].split()[3:])
    return {"TLD_DNSKEY": tld_dnskey}


def _check_direct_dnskey_response(zone):
    query = isctest.query.create(zone, "DNSKEY")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.noerror(response)
    assert response.flags & dns.flags.AA
    assert (
        response.get_rrset(
            response.answer,
            dns.name.from_text(zone),
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
        )
        is not None
    ), response


def _check_direct_ds_response(zone):
    query = isctest.query.create(zone, "DS")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.noerror(response)
    assert response.flags & dns.flags.AA
    assert (
        response.get_rrset(
            response.answer,
            dns.name.from_text(zone),
            dns.rdataclass.IN,
            dns.rdatatype.DS,
        )
        is not None
    ), response


def test_repro_5874_direct_forged_nsec3_response_has_child_signer():
    _check_direct_dnskey_response("tld.test.")
    _check_direct_dnskey_response(ATTACKER)
    _check_direct_ds_response(ATTACKER)

    query = isctest.query.create(VICTIM, "A")
    response = isctest.query.tcp(query, AUTH)

    isctest.check.nxdomain(response)
    assert response.flags & dns.flags.AA

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


def test_repro_5874_resolver_rejects_child_signed_nsec3_parent_proof():
    query = isctest.query.create(VICTIM, "A")
    response = isctest.query.tcp(query, RESOLVER)

    isctest.check.servfail(response)
    isctest.check.noadflag(response)
