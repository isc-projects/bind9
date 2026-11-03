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

import base64
import os
import shutil

import dns.flags
import dns.rdata
import dns.rdatatype
import pytest

from isctest.algorithms import MLDSA44
from isctest.template import NS1, zones
from isctest.zone import FileZoneKey, Zone

import isctest
import isctest.mark

pytestmark = [
    isctest.mark.with_algorithm("MLDSA44"),
    pytest.mark.extra_artifacts(
        [
            "ns*/dsset-*",
            "ns*/zones/*.db",
            "ns*/zones/*.db.signed",
        ]
    ),
]


def bootstrap():
    # configure_root() signs with the default algorithm, so drive the steps
    # here to sign the root zone with ML-DSA-44 keys
    root = Zone(".", NS1, signed=True)
    root.keys = [
        FileZoneKey.generate(root, "-f KSK", alg=MLDSA44),
        FileZoneKey.generate(root, alg=MLDSA44),
    ]
    root.render(template="_common/zones/root.db.j2.manual")
    root.sign()

    return {
        "trust_anchors": root.trust_anchors(),
        "zones": zones([root]),
    }


def test_mldsa_keygen_seed():
    """
    dnssec-keygen stores the 32-byte seed as the ML-DSA-44 private key.
    """
    privates = list(Path("ns1/keys").glob("K*.private"))
    assert len(privates) == 2
    for private in privates:
        seed = next(
            line.split()[1]
            for line in private.read_text(encoding="ascii").splitlines()
            if line.startswith("PrivateKey:")
        )
        assert len(base64.b64decode(seed)) == 32


def test_mldsa_verify():
    isctest.run.EnvCmd("VERIFY")("-o . zones/root.db.signed", cwd="ns1")


def test_mldsa_authoritative_and_resolver(ns1, ns2):
    msg = isctest.query.create(".", "SOA")
    authoritative = isctest.query.tcp(msg, ns1.ip)
    validated = isctest.query.tcp(msg, ns2.ip)
    isctest.check.noerror(authoritative)
    isctest.check.same_answer(authoritative, validated)
    isctest.check.adflag(validated)
    rrsigs = [
        rrset for rrset in validated.answer if rrset.rdtype == dns.rdatatype.RRSIG
    ]
    assert rrsigs
    for rrset in rrsigs:
        for signature in rrset:
            assert signature.algorithm == MLDSA44.number
            assert len(signature.signature) == 2420


def test_mldsa_udp_truncation(ns1, ns2):
    msg = isctest.query.create(".", "DNSKEY")
    response = isctest.query.udp(msg, ns1.ip)
    assert response.flags & dns.flags.TC
    response = isctest.query.tcp(msg, ns2.ip)
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    keys = response.find_rrset(response.answer, ".", "IN", "DNSKEY")
    assert len(keys) == 2
    assert all(key.algorithm == MLDSA44.number and len(key.key) == 1312 for key in keys)


def draft_key():
    return (
        Path(os.environ["TOP_SRCDIR"])
        / "tests/dns/testdata/dst"
        / "Kexample.com.+018+59829"
    )


def test_mldsa_draft_ds():
    ds = isctest.run.cmd(
        [os.environ["DSFROMKEY"], "-a", "sha-256", f"{draft_key()}.key"]
    ).out.split()
    assert ds[:6] == ["example.com.", "IN", "DS", "59829", "18", "2"]
    assert "".join(ds[6:]).lower() == (
        "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa"
    )


@pytest.mark.parametrize(
    "seed",
    [None, bytes(31), bytes(33), bytes(32)],
    ids=["missing", "short", "long", "mismatch"],
)
def test_mldsa_bad_private_seed(tmp_path, seed):
    """
    Reject a missing seed, wrong seed lengths, and a seed that doesn't
    match the DNSKEY.
    """
    key = draft_key()
    shutil.copyfile(f"{key}.key", tmp_path / f"{key.name}.key")
    private = "Private-key-format: v1.3\nAlgorithm: 18 (MLDSA44)\n"
    if seed is not None:
        private += f"PrivateKey: {base64.b64encode(seed).decode('ascii')}\n"
    (tmp_path / f"{key.name}.private").write_text(private, encoding="ascii")
    result = isctest.run.cmd(
        [os.environ["SETTIME"], "-p", "all", key.name],
        cwd=tmp_path,
        raise_on_exception=False,
    )
    assert result.rc != 0
    assert "private key is invalid" in result.err


def test_mldsa_policy_keygen(tmp_path):
    config = tmp_path / "policy.conf"
    config.write_text(
        'dnssec-policy "mldsa" { keys { csk lifetime unlimited algorithm MLDSA44; }; };\n',
        encoding="ascii",
    )
    key = isctest.run.cmd(
        [os.environ["KEYGEN"], "-k", "mldsa", "-l", str(config), "policy.example."],
        cwd=tmp_path,
    ).out.strip()
    text = (tmp_path / f"{key}.key").read_text(encoding="ascii")
    record = next(line for line in text.splitlines() if not line.startswith(";"))
    key = dns.rdata.from_text("IN", "DNSKEY", record.split("DNSKEY", 1)[1])
    assert key.algorithm == MLDSA44.number
    assert len(key.key) == 1312
