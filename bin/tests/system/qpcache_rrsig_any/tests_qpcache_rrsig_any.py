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

"""
A signature cannot cover a DNS meta-type. An RRSIG whose Type-Covered
field is one of NONE/ANY/AXFR/IXFR/MAILA/MAILB/OPT/TSIG/TKEY is
malformed and must be rejected by the resolver. ns3 picks the
Type-Covered field from the leftmost label of QNAME.
"""

from dns import rdatatype

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/named.run",
    ]
)


META_TYPES = ["ANY", "AXFR", "IXFR", "MAILA", "MAILB", "OPT", "TSIG", "TKEY"]


def any_query(qname):
    """
    Standalone RRSIG queries are rejected before any fetch is made, so
    use an ANY query to make the resolver fetch the lone RRSIG from ans3;
    with DO set, a cached signature would be returned in the answer.
    """
    msg = isctest.query.create(qname, "ANY", dnssec=True, ad=False)
    return isctest.query.tcp(msg, "10.53.0.2")


@pytest.mark.parametrize("meta_type", META_TYPES)
def test_rrsig_covers_metatype_is_servfail(meta_type):
    res = any_query(f"{meta_type.lower()}.attacker.test.")
    isctest.check.servfail(res)


def test_rrsig_covers_ordinary_type_is_answered():
    """
    The same query is answered when the RRSIG covers an ordinary type,
    so the SERVFAIL above is caused by the malformed RRSIG.
    """
    res = any_query("a.attacker.test.")
    isctest.check.noerror(res)
    assert [rrset.rdtype for rrset in res.answer] == [rdatatype.RRSIG], res


@pytest.mark.parametrize("meta_type", META_TYPES)
def test_dig_nobesteffort_rejects_malformed_rrsig(meta_type, named_port):
    """
    With +nobesteffort, dig uses the same strict parser path that the
    recursive resolver uses, so a malformed RRSIG covering a meta-type
    is rejected before being printed.
    """
    dig = isctest.run.EnvCmd("DIG", f"-p {named_port}")
    qname = f"{meta_type.lower()}.attacker.test."
    res = dig(
        f"+nobesteffort +tries=1 +time=5 @10.53.0.3 {qname} RRSIG",
        raise_on_exception=False,
    )
    assert ";; Got bad packet: FORMERR" in res.out
    assert "ANSWER SECTION" not in res.out


@pytest.mark.parametrize("meta_type", META_TYPES)
def test_dig_besteffort_shows_malformed_rrsig(meta_type, named_port):
    """
    The default dig parser runs in +besteffort mode, which intentionally
    keeps wire-level inspection working: the malformed RRSIG is still
    printed so operators can debug what an upstream actually sent.
    """
    dig = isctest.run.EnvCmd("DIG", f"-p {named_port}")
    qname = f"{meta_type.lower()}.attacker.test."
    res = dig(f"+tries=1 +time=5 @10.53.0.3 {qname} RRSIG")
    assert "ANSWER SECTION" in res.out
    assert "RRSIG" in res.out
