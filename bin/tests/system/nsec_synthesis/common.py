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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.mark

SIGNED_ZONE_MARKS = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/dsset-*",
            "ans*/keys.json",
            "ans*/zones/*.db",
            "ans*/zones/*.db.signed",
        ]
    ),
]


def make_key(zone: str):
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
