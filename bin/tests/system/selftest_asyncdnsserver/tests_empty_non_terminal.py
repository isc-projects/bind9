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

SIGNZONE_PARAMS = {
    NSEC_ZONE: "",
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
