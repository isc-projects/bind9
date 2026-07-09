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

from re import compile as Re

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/db-*",
        "ns*/dsset-*",
        "ns*/jn-*",
        "ns*/K*",
        "ns*/*.conf",
        "ns*/*.db",
        "ns*/*.jnl",
        "ns*/*.mirror",
        "ns*/*.nzf*",
        "ns*/*.nzd*",
        "ns*/*.signed",
    ]
)


def _rrset(response, section, owner, rdtype):
    return response.get_rrset(
        section,
        dns.name.from_text(owner),
        dns.rdataclass.IN,
        rdtype,
    )


def test_mirror_zone_ns_answer_adds_in_zone_address(ns3):
    with ns3.watch_log_from_start() as watcher:
        watcher.wait_for_line(Re(r"zone verify-csk/IN: mirror zone is now in use"))

    query = isctest.query.create("verify-csk.", "NS", dnssec=False, rd=False, ad=False)
    response = isctest.query.udp(query, ns3.ip, source="10.53.0.1")

    isctest.check.noerror(response)
    isctest.check.noaaflag(response)

    answer = _rrset(response, response.answer, "verify-csk.", dns.rdatatype.NS)
    expected_answer = dns.rrset.from_text(
        "verify-csk.", 3600, "IN", "NS", "ns2.verify-csk."
    )
    assert answer is not None, response.to_text()
    isctest.check.rrsets_equal(answer, expected_answer)

    additional = _rrset(
        response, response.additional, "ns2.verify-csk.", dns.rdatatype.A
    )
    expected_additional = dns.rrset.from_text(
        "ns2.verify-csk.", 3600, "IN", "A", "10.53.0.2"
    )
    assert additional is not None, response.to_text()
    isctest.check.rrsets_equal(additional, expected_additional)
