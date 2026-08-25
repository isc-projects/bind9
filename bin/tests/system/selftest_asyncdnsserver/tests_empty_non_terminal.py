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
"""
isctest.asyncserver denial of existence below an empty non-terminal

In every zone ans1 serves here, ent.<zone>. exists only through
deep.ent.<zone>., so the closest encloser of y.ent.<zone>. is ent.<zone>. and
the wildcard the NXDOMAIN proof has to deny is *.ent.<zone>.  A closest
encloser walked up with dns.zone.get_node() steps over the empty non-terminal,
because dnspython creates no node for it, and lands on the zone apex instead.

Walking up over the nodes the zone does have is not enough either.  RFC 5155
1.3 calls what an NSEC3 proof needs the closest *provable* encloser, and 7.1
leaves an empty non-terminal derived only from an insecure delegation with no
NSEC3 of its own, so in optout.test. the two enclosers differ: ent.<zone>. is
both, while for ent2.<zone>. only the apex is provable.

optout.test. and salt.test. also exercise the NSEC3 parameters, which are
Opt-Out in the first zone and a non-empty salt in the second; a proof built
with hardcoded parameters finds none of the records it needs in either.
"""

import dns.dnssec
import dns.dnssectypes
import dns.message
import dns.name
import dns.rdatatype
import pytest

from isctest.template import ANS1, NS2

import isctest
import isctest.zone

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "ans*/dsset-*",
        "ans*/zones/*.db",
        "ans*/zones/*.db.signed",
    ]
)

NSEC_ZONE = "nsec.test."
NSEC3_ZONE = "nsec3.test."
OPTOUT_ZONE = "optout.test."
SALTED_ZONE = "salt.test."

SALT = bytes.fromhex("DEADBEEF")

SIGNZONE_PARAMS = {
    NSEC_ZONE: "",
    NSEC3_ZONE: "-3 -",
    OPTOUT_ZONE: "-3 - -A",
    SALTED_ZONE: f"-3 {SALT.hex()}",
}


def bootstrap():
    trust_anchors = []
    for name, sign_params in SIGNZONE_PARAMS.items():
        zone = isctest.zone.Zone(name, ANS1, signed=True)
        zone.configure(sign_params=sign_params)
        trust_anchors += zone.trust_anchors("static-key")
    return {"trust_anchors": trust_anchors}


def auth(
    qname: str, qtype: dns.rdatatype.RdataType = dns.rdatatype.A
) -> dns.message.Message:
    msg = isctest.query.create(qname, qtype, rd=False)
    return isctest.query.udp(msg, ANS1.ip, timeout=3, attempts=3)


def resolve(qname: str) -> dns.message.Message:
    msg = isctest.query.create(qname, dns.rdatatype.A)
    return isctest.query.tcp(msg, NS2.ip, timeout=10, attempts=1)


def owners(section: list, rdtype: dns.rdatatype.RdataType) -> set:
    return {rrset.name for rrset in section if rrset.rdtype == rdtype}


def nsec3_owner(zone: str, name: str = "@", salt: bytes | None = None) -> dns.name.Name:
    """
    The owner of the NSEC3 record for `name`, given relative to `zone`: the
    name the record is hashed from, which is the one it matches or, for a
    covering record, the last existing name before the gap it spans.
    """
    hashed = dns.dnssec.nsec3_hash(
        dns.name.from_text(name, origin=dns.name.from_text(zone)),
        salt,
        0,
        dns.dnssectypes.NSEC3Hash.SHA1,
    )
    return dns.name.from_text(f"{hashed}.{zone}")


def test_nsec_denial_uses_empty_non_terminal_as_closest_encloser():
    """
    RFC 4035 3.1.3.2: an NXDOMAIN denies the QNAME and the wildcard.  The
    wildcard is *.ent.nsec.test., which sorts between a.nsec.test. and
    deep.ent.nsec.test.; an NSEC denying *.nsec.test. instead proves nothing
    about the name that was asked for.
    """
    res = auth(f"y.ent.{NSEC_ZONE}")
    isctest.check.nxdomain(res)
    assert owners(res.authority, dns.rdatatype.NSEC) == {
        dns.name.from_text(f"deep.ent.{NSEC_ZONE}"),  # covers y.ent.nsec.test.
        dns.name.from_text(f"a.{NSEC_ZONE}"),  # covers *.ent.nsec.test.
    }


def test_nsec_denial_validates():
    res = resolve(f"y.ent.{NSEC_ZONE}")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)


# The NSEC3 cases come last: each of them can fail in a way that raises out of
# the prover, which takes the whole server down -- including the nsec.test.
# zone checked above.  They are ordered so that a server which only gets part
# of the way still reports the first case it cannot handle.


def test_nsec3_denial_uses_empty_non_terminal_as_closest_encloser():
    """
    RFC 5155 7.2.2: an NXDOMAIN needs a closest encloser proof.  m.nsec3.test.
    exists only to keep the three records distinct: without it the NSEC3
    matching the closest encloser would cover the wildcard as well.
    """
    res = auth(f"y.ent.{NSEC3_ZONE}")
    isctest.check.nxdomain(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(NSEC3_ZONE, "ent"),  # matches the closest encloser
        nsec3_owner(NSEC3_ZONE, "ns"),  # covers y.ent.nsec3.test.
        nsec3_owner(NSEC3_ZONE, "m"),  # covers *.ent.nsec3.test.
    }


def test_nsec3_denial_validates():
    res = resolve(f"y.ent.{NSEC3_ZONE}")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)


def test_salted_nsec3_denial_hashes_with_the_zones_parameters():
    """
    RFC 5155 4: the hash parameters are the ones in the zone's NSEC3PARAM.
    salt.test. is the same shape as nsec3.test. signed with a salt, so a proof
    hashed with no salt looks up three names none of which is in the chain.
    """
    res = auth(f"y.ent.{SALTED_ZONE}")
    isctest.check.nxdomain(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(SALTED_ZONE, "ent", SALT),  # matches the closest encloser
        nsec3_owner(SALTED_ZONE, salt=SALT),  # covers y.ent.salt.test.
        nsec3_owner(SALTED_ZONE, "deep.ent", SALT),  # covers *.ent.salt.test.
    }


def test_salted_nsec3_denial_validates():
    res = resolve(f"y.ent.{SALTED_ZONE}")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)


def test_optout_denial_uses_empty_non_terminal_as_closest_encloser():
    """
    RFC 5155 7.1: Opt-Out exempts only the empty non-terminals derived from
    the insecure delegations it covers.  ent.optout.test. is not one of those
    -- it exists through the authoritative deep.ent.optout.test. -- so it is
    matched by an NSEC3, and asking for one covering it instead fails.
    """
    res = auth(f"y.ent.{OPTOUT_ZONE}")
    isctest.check.nxdomain(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(OPTOUT_ZONE, "ent"),  # matches the closest encloser
        nsec3_owner(OPTOUT_ZONE, "deep.ent"),  # covers y.ent.optout.test.
        nsec3_owner(OPTOUT_ZONE, "shim2"),  # covers *.ent.optout.test.
    }


def test_optout_denial_validates():
    """
    RFC 5155 9.2 makes an Opt-Out chain unable to prove that a name does not
    exist, since the gap the QNAME falls in may hold an insecure delegation,
    so the answer is NXDOMAIN without the AD bit rather than a secure one.  A
    proof the validator could not follow at all would be SERVFAIL.
    """
    res = resolve(f"y.ent.{OPTOUT_ZONE}")
    isctest.check.nxdomain(res)
    isctest.check.noadflag(res)


def test_optout_denial_falls_back_to_the_closest_provable_encloser():
    """
    RFC 5155 1.3: what the proof needs is the closest *provable* encloser.
    ent2.optout.test. exists only through the insecure delegation
    deep.ent2.optout.test., which the Opt-Out chain skips, so RFC 5155 7.1
    leaves it with no NSEC3 and the proof has to climb past it to the apex.
    Both a closest encloser taken from the nodes the zone has and one taken
    from the NSEC3 chain answer ent.optout.test. above; this is the case that
    tells them apart.
    """
    res = auth(f"x.ent2.{OPTOUT_ZONE}")
    isctest.check.nxdomain(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(OPTOUT_ZONE),  # matches the closest provable encloser
        nsec3_owner(OPTOUT_ZONE, "deep.ent"),  # covers ent2.optout.test.
        nsec3_owner(OPTOUT_ZONE, "shim1"),  # covers *.optout.test.
    }


def test_optout_denial_falls_back_and_validates():
    res = resolve(f"x.ent2.{OPTOUT_ZONE}")
    isctest.check.nxdomain(res)
    isctest.check.noadflag(res)


def test_optout_nodata_at_empty_non_terminal_without_nsec3():
    """
    RFC 5155 7.1 leaves ent2.optout.test. with no NSEC3 to match, so the
    NODATA proof is the closest provable encloser proof, as for the NXDOMAIN
    above.
    """
    res = auth(f"ent2.{OPTOUT_ZONE}")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(OPTOUT_ZONE),  # matches the closest provable encloser
        nsec3_owner(OPTOUT_ZONE, "deep.ent"),  # covers ent2.optout.test.
    }


def test_optout_nodata_for_ds_at_insecure_delegation():
    """
    RFC 5155 7.2.4: with no NSEC3 matching the delegation, a DS query gets
    the closest provable encloser proof instead.
    """
    res = auth(f"deep.ent2.{OPTOUT_ZONE}", dns.rdatatype.DS)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert owners(res.authority, dns.rdatatype.NSEC3) == {
        nsec3_owner(OPTOUT_ZONE),  # matches the closest provable encloser
        nsec3_owner(OPTOUT_ZONE, "deep.ent"),  # covers ent2.optout.test.
    }
