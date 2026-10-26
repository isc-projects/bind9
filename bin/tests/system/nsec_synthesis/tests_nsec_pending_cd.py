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

F004_ZONE = "f004.test."
ATTACKER = f"attacker.{F004_ZONE}"
VICTIM = f"victim.{F004_ZONE}"
POISON_NEXT = f"b.{VICTIM}"
VICTIM_A = "203.0.113.1"
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


def _make_key(zone: str):
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
    keys = {F004_ZONE: _make_key(F004_ZONE)}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    dnskey = "".join(keys[f"{F004_ZONE}"]["dnskey"].split()[3:])
    return {"DNSKEY": dnskey}


def _has_a(response, owner, address):
    rrset = response.get_rrset(
        response.answer, owner, dns.rdataclass.IN, dns.rdatatype.A
    )
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def _check_attacker_nsec(response, section):
    nsec = response.get_rrset(
        section, f"{ATTACKER}", dns.rdataclass.IN, dns.rdatatype.NSEC
    )
    assert nsec is not None, response.to_text()
    assert nsec[0].next == dns.name.from_text(POISON_NEXT), response.to_text()

    rrsig = response.get_rrset(
        section,
        f"{ATTACKER}",
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.NSEC,
    )
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(f"{F004_ZONE}"), response.to_text()
    assert rrsig[0].key_tag == 9999, response.to_text()


def test_pending_trust_nsec_cd_cache_poisoning():
    """
    Reproducer for #5872:
    F-004 Cache Poisoning via Pending-Trust NSEC in Aggressive Cache
    """
    # Step 1: Prime SOA parent (and DNSKEY as subquery)
    soa = isctest.query.tcp(isctest.query.create(F004_ZONE, "SOA"), RESOLVER)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Step 2: Inject Forged NSEC via CD=1 Query
    poison = isctest.query.tcp(
        isctest.query.create(ATTACKER, "NSEC", cd=True), RESOLVER
    )
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    _check_attacker_nsec(poison, poison.answer)

    # Step 3: Exploit Against Victim Domain
    response = isctest.query.tcp(isctest.query.create(VICTIM, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert _has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert (
        response.get_rrset(
            response.authority, ATTACKER, dns.rdataclass.IN, dns.rdatatype.NSEC
        )
        is None
    )

    # Step 4: Exploit Against Stub Client
    response = isctest.query.tcp(
        isctest.query.create(VICTIM, "A", dnssec=False), RESOLVER
    )
    isctest.check.noerror(response)
    assert _has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert (
        response.get_rrset(
            response.authority, ATTACKER, dns.rdataclass.IN, dns.rdatatype.NSEC
        )
        is None
    )

    # Step 5: Verify Upstream Queries
    with open("ans1/ans.run", "r", encoding="utf-8") as file:
        assert f"Received {VICTIM.rstrip('.')}/IN/A" in file.read()
