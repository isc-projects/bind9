#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

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

PARENT = "p.test."
EVIL = "evil.p.test."
POISON = f"0.{EVIL}"
POISON_NEXT = "zzz.p.test."
TARGET = f"target.{PARENT}"
TARGET_A = "192.0.2.77"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "ans*/keys.json",
    ]
)


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
    keys = {PARENT: _make_key()}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    parent_dnskey = "".join(keys[PARENT]["dnskey"].split()[3:])
    return {"PARENT_DNSKEY": parent_dnskey}


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


def _has_a(response, owner, address):
    rrset = _rrset(response, response.answer, owner, dns.rdatatype.A)
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def _check_malicious_nsec(response, section):
    nsec = _rrset(response, section, POISON, dns.rdatatype.NSEC)
    assert nsec is not None, response.to_text()
    assert nsec[0].next == dns.name.from_text(POISON_NEXT), response.to_text()

    rrsig = _rrset(
        response,
        section,
        POISON,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.NSEC,
    )
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(PARENT), response.to_text()
    assert rrsig[0].key_tag == 12345, response.to_text()


def _prime_parent_for_aggressive_nsec():
    soa = _query(RESOLVER, PARENT, "SOA")
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    nsec = _query(RESOLVER, PARENT, "NSEC")
    isctest.check.noerror(nsec)
    isctest.check.adflag(nsec)


def test_direct_insecure_child_nsec_next_fixture():
    poison = _query(AUTH, POISON, "NSEC")
    isctest.check.noerror(poison)
    assert poison.flags & dns.flags.AA
    _check_malicious_nsec(poison, poison.answer)


def test_resolver_does_not_synth_from_insecure_child_nsec():
    _prime_parent_for_aggressive_nsec()

    poison = _query(RESOLVER, POISON, "NSEC")
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    _check_malicious_nsec(poison, poison.answer)

    response = _query(RESOLVER, TARGET, "A")
    isctest.check.noerror(response)
    assert _has_a(response, TARGET, TARGET_A), response.to_text()
    isctest.check.adflag(response)
    assert _rrset(response, response.authority, POISON, dns.rdatatype.NSEC) is None
