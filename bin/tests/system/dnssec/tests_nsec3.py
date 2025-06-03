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

import os
from pathlib import Path

import pytest

pytest.importorskip("dns", minversion="2.5.0")
from dns.dnssectypes import NSEC3Hash
import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.hypothesis.strategies import dns_names
import isctest
import isctest.name

from hypothesis import assume, given

SUFFIX = dns.name.from_text("nsec3.example.")
AUTH = "10.53.0.3"
RESOLVER = "10.53.0.4"
TIMEOUT = 5
ZONE = isctest.name.ZoneAnalyzer.read_path(
    Path(os.environ["builddir"]) / "dnssec/ns3/nsec3.example.db.in", origin=SUFFIX
)


def nsec3_covers(rrset: dns.rrset.RRset, hashed_name: dns.name.Name) -> bool:
    """
    Test if 'hashed_name' is covered by an NSEC3 record in 'rrset'.
    """
    prev_name = rrset.name

    for nsec3 in rrset:
        next_name = nsec3.next_name(SUFFIX)

        # Single name case.
        if prev_name == next_name:
            return prev_name != hashed_name

        # Standard case.
        if prev_name < next_name:
            if prev_name < hashed_name < next_name:
                return True

        # The cover wraps.
        if next_name < prev_name:
            # Case 1: The covered name is at the end of the chain.
            if hashed_name > prev_name:
                return True
            # Case 2: The covered name is at the start of the chain.
            if hashed_name < next_name:
                return True
    return False


def check_nsec3_covers(name: dns.name.Name, response: dns.message.Message) -> None:
    name_is_covered = False

    nhash = dns.dnssec.nsec3_hash(
        name, salt=None, iterations=0, algorithm=NSEC3Hash.SHA1
    )
    hashed_name = dns.name.from_text(nhash, SUFFIX)

    for rrset in response.authority:
        if rrset.match(dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE):
            name_is_covered = nsec3_covers(rrset, hashed_name)
            if name_is_covered:
                break

    assert (
        name_is_covered
    ), f"Expected covering NSEC3 for {name} (hash={nhash}) not found:\n {response}"


@pytest.mark.parametrize(
    "server", [pytest.param(AUTH, id="ns3"), pytest.param(RESOLVER, id="ns4")]
)
@given(name=dns_names(suffix=SUFFIX))
# @given(name=just(dns.name.from_text(f"\000.\001.{SUFFIX}")))
# @given(name=just(dns.name.from_text(f"a.wild.{SUFFIX}")))
def test_dnssec_nsec3_nxdomain(server, name: dns.name.Name, named_port: int) -> None:
    noqname_test(server, name, named_port)


@pytest.mark.parametrize(
    "server", [pytest.param(AUTH, id="ns3"), pytest.param(RESOLVER, id="ns4")]
)
@given(name=dns_names(suffix=ZONE.reachable.union(ZONE.ents)))
def test_dnssec_nsec3_subdomain_nxdomain(
    server, name: dns.name.Name, named_port: int
) -> None:
    noqname_test(server, name, named_port)


def noqname_test(server, name: dns.name.Name, named_port: int) -> None:
    # randomly generated name must not exist
    assume(name not in (ZONE.all_existing_names))

    # name must not be under a delegation or DNAME:
    # it would not work with resolver ns4
    assume(
        not isctest.name.is_related_to_any(
            name,
            (dns.name.NameRelation.EQUAL, dns.name.NameRelation.SUBDOMAIN),
            ZONE.reachable_delegations.union(ZONE.reachable_dnames),
        )
    )

    query = dns.message.make_query(
        name, dns.rdatatype.A, use_edns=True, want_dnssec=True
    )
    response = isctest.query.tcp(query, server, named_port, timeout=TIMEOUT)
    isctest.check.is_response_to(response, query)
    assert response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)

    ce, nce = ZONE.closest_encloser(name)
    # Response has NSEC3 that covers the next closer name
    check_nsec3_covers(nce, response)

    wname = ZONE.source_of_synthesis(name)
    if wname in ZONE.reachable_wildcards:
        wname_parent = dns.name.Name(wname[1:])
        assert name.is_subdomain(wname_parent)
        # expecting wildcard response with a signed A RRset
        assert response.rcode() is dns.rcode.NOERROR
        answer_sig = response.get_rrset(
            section="ANSWER",
            name=name,
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.RRSIG,
            covers=dns.rdatatype.A,
        )
        assert answer_sig is not None
        assert len(answer_sig) == 1
        # RRSIG labels field, RFC 4034 section 3.1.3 does not count:
        # - root label
        # - leftmost * label
        wildcard_parent_labels = answer_sig[0].labels + 1  # add root but not leftmost *
        assert wildcard_parent_labels < len(name)
        # ce should be wildcard name w/o wildcard label, nce one label longer
        assert ce == name.split(wildcard_parent_labels)[1]
        assert nce == name.split(wildcard_parent_labels + 1)[1]
    else:
        # no wildcard synthesis -> NXDOMAIN
        assert response.rcode() is dns.rcode.NXDOMAIN
        # Response must have closest encloser NSEC3
        ce_hash = dns.dnssec.nsec3_hash(
            ce, salt=None, iterations=0, algorithm=NSEC3Hash.SHA1
        )
        ce_nsec3 = dns.name.from_text(ce_hash, SUFFIX)

        ce_nsec3_match = False
        for rrset in response.authority:
            if rrset.match(
                ce_nsec3, dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
            ):
                ce_nsec3_match = True
        assert (
            ce_nsec3_match
        ), f"Expected matching NSEC3 for {ce} (hash={ce_hash}) not found:\n {response}"

        # Response has NSEC3 that covers the wildcard
        check_nsec3_covers(wname, response)
