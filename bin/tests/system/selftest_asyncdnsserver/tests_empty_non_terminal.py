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

SIGNZONE_PARAMS = {
    NSEC_ZONE: "",
    NSEC3_ZONE: "-3 -",
}


def bootstrap():
    trust_anchors = []
    for name, sign_params in SIGNZONE_PARAMS.items():
        zone = isctest.zone.Zone(name, ANS1, signed=True)
        zone.configure(sign_params=sign_params)
        trust_anchors += zone.trust_anchors("static-key")
    return {"trust_anchors": trust_anchors}


def auth(qname: str) -> dns.message.Message:
    msg = isctest.query.create(qname, dns.rdatatype.A, rd=False)
    return isctest.query.udp(msg, ANS1.ip, timeout=3, attempts=3)


def resolve(qname: str) -> dns.message.Message:
    msg = isctest.query.create(qname, dns.rdatatype.A)
    return isctest.query.tcp(msg, NS2.ip, timeout=10, attempts=1)


def owners(section: list, rdtype: dns.rdatatype.RdataType) -> set:
    return {rrset.name for rrset in section if rrset.rdtype == rdtype}


def nsec3_owner(zone: str, name: str = "@") -> dns.name.Name:
    """
    The owner of the NSEC3 record for `name`, given relative to `zone`: the
    name the record is hashed from, which is the one it matches or, for a
    covering record, the last existing name before the gap it spans.
    """
    hashed = dns.dnssec.nsec3_hash(
        dns.name.from_text(name, origin=dns.name.from_text(zone)),
        None,
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
