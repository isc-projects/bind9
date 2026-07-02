#!/usr/bin/python3

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
A signature must cover a real, non-signature rdata type. An RRSIG whose
Type-Covered field is a meta-type (NONE/ANY/AXFR/IXFR/MAILA/MAILB/OPT/
TSIG/TKEY) or a signature type (RRSIG) is malformed and must be rejected
by the resolver. ns3 picks the Type-Covered field from the leftmost
label of QNAME.
"""

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "ns*/named.run",
    ]
)


META_TYPES = ["ANY", "AXFR", "IXFR", "MAILA", "MAILB", "OPT", "TSIG", "TKEY"]
# A signature covering a signature (RRSIG covering RRSIG) is not a meta-type,
# so it slipped past the meta-type hardening and tripped an assertion in the
# QP cache; make sure it is rejected too.
SIG_TYPES = ["RRSIG"]
REJECTED_TYPES = META_TYPES + SIG_TYPES


@pytest.mark.parametrize("covered_type", REJECTED_TYPES)
def test_rrsig_covers_rejected_type_is_servfail(covered_type):
    qname = f"{covered_type.lower()}.attacker.test."
    msg = isctest.query.create(qname, "RRSIG", dnssec=False, ad=False)
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.servfail(res)


@pytest.mark.parametrize("covered_type", REJECTED_TYPES)
def test_dig_nobesteffort_rejects_malformed_rrsig(covered_type, named_port):
    """
    With +nobesteffort, dig uses the same strict parser path that the
    recursive resolver uses, so a malformed RRSIG covering a meta-type
    or a signature type is rejected before being printed.
    """
    dig = isctest.run.EnvCmd("DIG", f"-p {named_port}")
    qname = f"{covered_type.lower()}.attacker.test."
    res = dig(
        f"+nobesteffort +tries=1 +time=5 @10.53.0.3 {qname} RRSIG",
        raise_on_exception=False,
    )
    assert ";; Got bad packet: FORMERR" in res.out
    assert "ANSWER SECTION" not in res.out


@pytest.mark.parametrize("covered_type", REJECTED_TYPES)
def test_dig_besteffort_shows_malformed_rrsig(covered_type, named_port):
    """
    The default dig parser runs in +besteffort mode, which intentionally
    keeps wire-level inspection working: the malformed RRSIG is still
    printed so operators can debug what an upstream actually sent.
    """
    dig = isctest.run.EnvCmd("DIG", f"-p {named_port}")
    qname = f"{covered_type.lower()}.attacker.test."
    res = dig(f"+tries=1 +time=5 @10.53.0.3 {qname} RRSIG")
    assert "ANSWER SECTION" in res.out
    assert "RRSIG" in res.out
