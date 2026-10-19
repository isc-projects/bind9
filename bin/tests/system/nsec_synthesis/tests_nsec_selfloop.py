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

import pytest

from isctest.run import EnvCmd
from isctest.template import TrustAnchor
from nsec_synthesis.common import check_nsec, get_nsec, has_a

import isctest

PARENT = "f007.test."
CHILD = "!.f007.test."
PROBE = f"probe.{CHILD}"
VICTIM = f"victim.{PARENT}"
VICTIM_A = "203.0.113.7"
AUTH = "10.53.0.3"
RESOLVER = "10.53.0.2"

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns3/K*",
        "ns3/child.f007.test.db",
        "ns3/child.f007.test.db.signed",
        "ns3/dsset-*",
        "ns3/f007.test.db",
        "ns3/f007.test.db.signed",
    ]
)


def _write_zone(path, text):
    Path(path).write_text(text, encoding="ascii")


def bootstrap():
    keygen = EnvCmd("KEYGEN", "-a ECDSA256 -q")
    dsfromkey = EnvCmd("DSFROMKEY", "-2")
    signer = EnvCmd("SIGNER", "-S -g")

    parent_ksk = keygen(f"-f KSK {PARENT}", cwd="ns3").out.strip()
    keygen(PARENT, cwd="ns3")
    child_ksk = keygen(f"-f KSK {CHILD}", cwd="ns3").out.strip()
    keygen(CHILD, cwd="ns3")

    child_ds = dsfromkey(f"{child_ksk}.key", cwd="ns3").out

    _write_zone(
        "ns3/child.f007.test.db",
        f"""$TTL 300
$ORIGIN {CHILD}
@ SOA ns.f007.test. hostmaster.f007.test. 1 3600 600 86400 300
@ NS ns.f007.test.
""",
    )
    _write_zone(
        "ns3/f007.test.db",
        f"""$TTL 300
$ORIGIN {PARENT}
@ SOA ns hostmaster 1 3600 600 86400 300
@ NS ns
ns A 10.53.0.3
victim A {VICTIM_A}
! NS ns.f007.test.
{child_ds}""",
    )

    signer(f"-o {CHILD} -f child.f007.test.db.signed child.f007.test.db", cwd="ns3")
    signer(f"-o {PARENT} -f f007.test.db.signed f007.test.db", cwd="ns3")

    dnskey = str(isctest.kasp.Key(parent_ksk, keydir="ns3").dnskey).split()
    contents = f'{" ".join(dnskey[4:7])} "{"".join(dnskey[7:])}"'

    return {"trust_anchors": [TrustAnchor(PARENT, "static-key", contents)]}


def test_direct_child_self_loop_nsec_fixture():
    response = isctest.query.tcp(isctest.query.create(PROBE, "A"), AUTH)
    isctest.check.nxdomain(response)
    isctest.check.aaflag(response)
    check_nsec(response, response.authority, CHILD, CHILD, CHILD)


def test_resolver_does_not_synth_parent_nxdomain_from_child_nsec():
    poison = isctest.query.tcp(isctest.query.create(PROBE, "A"), RESOLVER)
    isctest.check.nxdomain(poison)
    isctest.check.adflag(poison)
    check_nsec(poison, poison.authority, CHILD, CHILD, CHILD)

    response = isctest.query.tcp(isctest.query.create(VICTIM, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.authority, CHILD)
