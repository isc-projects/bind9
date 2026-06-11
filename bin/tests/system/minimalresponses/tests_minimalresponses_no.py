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

from dns.rcode import NOERROR, REFUSED, SERVFAIL

import pytest

from minimalresponses.common import (
    AEXAMPLE2_A,
    AEXAMPLE4_A,
    EXAMPLE2_NS,
    EXAMPLE4_NS,
    INPUTPARAMS,
    NSEXAMPLE2_A,
    NSEXAMPLE4_A,
    check,
    reconfig,
)

INPUTS = [
    # ns1 provides AUTHORITY and ADDITIONAL as it delegate those zone.
    ("ns1", "a.example2", "A", True, False, NOERROR, None, EXAMPLE2_NS, NSEXAMPLE2_A),
    ("ns1", "a.example4", "A", True, False, NOERROR, None, EXAMPLE4_NS, NSEXAMPLE4_A),
    ("ns1", "a.example2", "A", False, False, NOERROR, None, EXAMPLE2_NS, NSEXAMPLE2_A),
    ("ns1", "a.example4", "A", False, False, NOERROR, None, EXAMPLE4_NS, NSEXAMPLE4_A),
    # ns2 is authoritative on example2, so it gives us everything it can in any cases.
    (
        "ns2",
        "a.example2",
        "A",
        True,
        False,
        NOERROR,
        AEXAMPLE2_A,
        EXAMPLE2_NS,
        NSEXAMPLE2_A,
    ),
    (
        "ns2",
        "a.example2",
        "A",
        False,
        False,
        NOERROR,
        AEXAMPLE2_A,
        EXAMPLE2_NS,
        NSEXAMPLE2_A,
    ),
    ("ns2", "a.example4", "A", True, False, REFUSED, None, None, None),
    ("ns2", "a.example4", "A", False, False, REFUSED, None, None, None),
    # ns3 being resolver only and having the answer, no AUTHORITY or ADDITIONAL are added.
    # However, with RD=0 and no cache, it can't answer, so the root hints are provided
    # in AUTHORITY.
    ("ns3", "a.example2", "A", True, False, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", True, False, NOERROR, AEXAMPLE4_A, None, None),
    ("ns3", "a.example2", "A", True, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", True, True, NOERROR, AEXAMPLE4_A, None, None),
    ("ns3", "a.example2", "A", False, False, SERVFAIL, None, None, None),
    ("ns3", "a.example4", "A", False, False, SERVFAIL, None, None, None),
    ("ns3", "a.example2", "A", False, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", False, True, NOERROR, AEXAMPLE4_A, None, None),
    # ns4 is authoritative on example4, so gives us everything in any cases.
    # For example2, because it has the answer, it only provide the ANSWER section
    # (except with no cache and RD=0, where we got the root hint, because it can't do anything else)
    ("ns4", "a.example2", "A", True, True, NOERROR, AEXAMPLE2_A, None, None),
    (
        "ns4",
        "a.example4",
        "A",
        True,
        True,
        NOERROR,
        AEXAMPLE4_A,
        EXAMPLE4_NS,
        NSEXAMPLE4_A,
    ),
    ("ns4", "a.example2", "A", True, False, NOERROR, AEXAMPLE2_A, None, None),
    (
        "ns4",
        "a.example4",
        "A",
        True,
        False,
        NOERROR,
        AEXAMPLE4_A,
        EXAMPLE4_NS,
        NSEXAMPLE4_A,
    ),
    ("ns4", "a.example2", "A", False, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns4", "a.example2", "A", False, False, SERVFAIL, None, None, None),
    (
        "ns4",
        "a.example4",
        "A",
        False,
        False,
        NOERROR,
        AEXAMPLE4_A,
        EXAMPLE4_NS,
        NSEXAMPLE4_A,
    ),
    (
        "ns4",
        "a.example4",
        "A",
        False,
        True,
        NOERROR,
        AEXAMPLE4_A,
        EXAMPLE4_NS,
        NSEXAMPLE4_A,
    ),
    # Resolver always provides glues with associated NS for qtype=NS
    ("ns3", "example2", "NS", True, False, NOERROR, EXAMPLE2_NS, None, NSEXAMPLE2_A),
    ("ns3", "example2", "NS", False, False, SERVFAIL, None, None, None),
    ("ns3", "example2", "NS", False, True, NOERROR, EXAMPLE2_NS, None, NSEXAMPLE2_A),
    ("ns3", "example2", "NS", True, True, NOERROR, EXAMPLE2_NS, None, NSEXAMPLE2_A),
]


@pytest.fixture(scope="module", autouse=True)
def authsection_init(servers, templates):
    reconfig(servers, templates, "no")


@pytest.mark.parametrize(INPUTPARAMS, INPUTS)
def test_minimalresponses_no(
    ns, qname, qtype, rd, cached, rcode, answer, authority, additional
):
    check(ns, qname, qtype, rd, cached, rcode, answer, authority, additional)
