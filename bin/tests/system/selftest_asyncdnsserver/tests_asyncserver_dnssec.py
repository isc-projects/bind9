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
AsyncDnsServer responses built from zone data
"""

import dns.message
import dns.rdatatype
import pytest

from isctest.template import ANS1

import isctest

pytestmark = pytest.mark.extra_artifacts(["ans*/ans.run"])


def query(qname: str, qtype: str, dnssec: bool = False) -> dns.message.Message:
    msg = isctest.query.create(qname, qtype, dnssec=dnssec, rd=False)
    return isctest.query.udp(msg, ANS1.ip, timeout=3, attempts=3)


def rrsets(section: list, rdtype: dns.rdatatype.RdataType) -> list:
    return [rrset for rrset in section if rrset.rdtype == rdtype]


def test_wildcard_applies_at_closest_encloser():
    res = query("y.example.", "A")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 1)
    assert rrsets(res.answer, dns.rdatatype.A)[0][0].to_text() == "198.51.100.45"


def test_wildcard_occluded_by_empty_non_terminal():
    """
    RFC 4592 3.3.1: ent.example. is an empty non-terminal, so it -- not
    example. -- is the closest encloser of y.ent.example.  The source of
    synthesis is therefore *.ent.example., which does not exist, and "there is
    no search for an alternate".
    """
    res = query("y.ent.example.", "A")
    isctest.check.nxdomain(res)
    isctest.check.empty_answer(res)


def test_empty_non_terminal_is_nodata():
    res = query("ent.example.", "A")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert rrsets(res.authority, dns.rdatatype.SOA)


def test_nodata_through_cname_carries_soa():
    """
    RFC 2308 2.2: a Type 2 NODATA reached via a CNAME still carries the SOA.
    """
    res = query("foo.example.", "AAAA")
    isctest.check.noerror(res)
    assert rrsets(res.answer, dns.rdatatype.CNAME)
    assert rrsets(res.authority, dns.rdatatype.SOA)


def test_referral_with_do_carries_ds_and_rrsig():
    """
    The DS is only added when DO is set, so this is the one query that reaches
    QueryContext.get_rrsig() with a non-SOA RRset before qctx.node is set.
    """
    res = query("www.child.example.", "A", dnssec=True)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert rrsets(res.authority, dns.rdatatype.NS)
    assert rrsets(res.authority, dns.rdatatype.DS)
    assert rrsets(res.authority, dns.rdatatype.RRSIG)


def test_referral_without_do_has_no_ds():
    res = query("www.child.example.", "A")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert rrsets(res.authority, dns.rdatatype.NS)
    assert not rrsets(res.authority, dns.rdatatype.DS)


def test_ds_at_delegation_is_answered_from_parent():
    """
    Asked without DO on purpose: this zone carries an RRSIG but no NSEC or
    NSEC3 records, and a signed answer makes _noerror_response() ask for a
    non-existence proof the zone cannot supply.
    """
    res = query("child.example.", "DS")
    isctest.check.noerror(res)
    assert rrsets(res.answer, dns.rdatatype.DS)


def test_ds_below_delegation_is_referred():
    """
    The parent zone holds no data under the cut, so it must not deny that the
    name exists.
    """
    res = query("www.child.example.", "DS")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert rrsets(res.authority, dns.rdatatype.NS)


def test_ds_at_zone_apex_is_nodata():
    """
    A DS RRset lives in the parent zone, but the parent of example. is not
    served here while example. itself is, so the query must not be refused.
    """
    res = query("example.", "DS")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert rrsets(res.authority, dns.rdatatype.SOA)


def test_ds_for_root_is_refused():
    """
    The root has no parent zone to answer from and no root zone is served
    here either, so the query is refused, as for any other unserved name; a
    served root zone would answer NODATA from its apex, like example. above.
    """
    res = query(".", "DS")
    isctest.check.refused(res)
