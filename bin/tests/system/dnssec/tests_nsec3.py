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
import dns.rdtypes.ANY.RRSIG
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


def do_test_query(qname, qtype, server, named_port) -> dns.message.Message:
    query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
    response = isctest.query.tcp(query, server, named_port, timeout=TIMEOUT)
    isctest.check.is_response_to(response, query)
    assert response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
    return response


def assume_nx_and_no_delegation(qname):
    assume(qname not in ZONE.all_existing_names)

    # name must not be under a delegation or DNAME:
    # it would not work with resolver ns4
    assume(
        not isctest.name.is_related_to_any(
            qname,
            (dns.name.NameRelation.EQUAL, dns.name.NameRelation.SUBDOMAIN),
            ZONE.reachable_delegations.union(ZONE.reachable_dnames),
        )
    )


def nsec3_covers(rrset: dns.rrset.RRset, hashed_name: dns.name.Name) -> bool:
    """
    Test if 'hashed_name' is covered by an NSEC3 record in 'rrset', i.e. the name does not exist.
    """
    prev_name = rrset.name

    for nsec3 in rrset:
        assert nsec3.flags == 0, "opt-out not supported by test logic"
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
    """Given name provably does not exist"""
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
@given(qname=dns_names(suffix=SUFFIX))
def test_nxdomain(server, qname: dns.name.Name, named_port: int) -> None:
    """A real NXDOMAIN, no wildcards involved"""
    assume_nx_and_no_delegation(qname)
    wname = ZONE.source_of_synthesis(qname)
    assume(wname not in ZONE.reachable_wildcards)

    check_nxdomain(server, named_port, qname)


@pytest.mark.parametrize(
    "server", [pytest.param(AUTH, id="ns3"), pytest.param(RESOLVER, id="ns4")]
)
@given(qname=dns_names(suffix=ZONE.ents))
def test_ents(server, qname: dns.name.Name, named_port: int) -> None:
    """ENT can have a wildcard under it"""
    assume_nx_and_no_delegation(qname)

    wname = ZONE.source_of_synthesis(qname)
    # does qname match a wildcard under ENT?
    if wname in ZONE.reachable_wildcards:
        check_wildcard_synthesis(server, named_port, qname)
    else:
        check_nxdomain(server, named_port, qname)


@pytest.mark.parametrize(
    "server", [pytest.param(AUTH, id="ns3"), pytest.param(RESOLVER, id="ns4")]
)
@given(qname=dns_names(suffix=ZONE.reachable_wildcard_parents))
def test_wildcard_synthesis(server, qname: dns.name.Name, named_port: int) -> None:
    assume(qname not in ZONE.all_existing_names)

    wname = ZONE.source_of_synthesis(qname)
    assume(wname in ZONE.reachable_wildcards)

    check_wildcard_synthesis(server, named_port, qname)


@pytest.mark.parametrize(
    "server", [pytest.param(AUTH, id="ns3"), pytest.param(RESOLVER, id="ns4")]
)
@given(qname=dns_names(suffix=ZONE.reachable_wildcard_parents))
def test_wildcard_nodata(server, qname: dns.name.Name, named_port: int) -> None:
    assume(qname not in ZONE.all_existing_names)

    wname = ZONE.source_of_synthesis(qname)
    assume(wname in ZONE.reachable_wildcards)

    check_wildcard_nodata(server, named_port, qname)


def check_nsec3_owner(owner: dns.name.Name, response):
    """Check response has NSEC3 RR matching given owner name, i.e. the name exists."""
    name_hash = dns.dnssec.nsec3_hash(
        owner, salt=None, iterations=0, algorithm=NSEC3Hash.SHA1
    )
    nsec3_owner = dns.name.from_text(name_hash, SUFFIX)

    nsec3_found = False
    for rrset in response.authority:
        if rrset.match(
            nsec3_owner, dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
        ):
            nsec3_found = True
    assert (
        nsec3_found
    ), f"Expected matching NSEC3 for {owner} (hash={name_hash}) not found:\n{response}"


def check_wildcard_nodata(server, named_port: int, qname: dns.name.Name) -> None:
    response = do_test_query(qname, dns.rdatatype.AAAA, server, named_port)
    assert response.rcode() is dns.rcode.NOERROR

    ce, nce = ZONE.closest_encloser(qname)
    check_nsec3_owner(ce, response)
    check_nsec3_covers(nce, response)

    wname = ZONE.source_of_synthesis(qname)
    # expecting proof that wildcard owner does not have rdatatype requested
    check_nsec3_owner(wname, response)


def check_nxdomain(server, named_port: int, qname: dns.name.Name) -> None:
    response = do_test_query(qname, dns.rdatatype.A, server, named_port)
    assert response.rcode() is dns.rcode.NXDOMAIN

    ce, nce = ZONE.closest_encloser(qname)
    check_nsec3_owner(ce, response)
    check_nsec3_covers(nce, response)

    wname = ZONE.source_of_synthesis(qname)
    check_nsec3_covers(wname, response)


def check_wildcard_synthesis(server, named_port: int, qname: dns.name.Name) -> None:
    """Expect wildcard response with a signed A RRset"""
    response = do_test_query(qname, dns.rdatatype.A, server, named_port)
    assert response.rcode() is dns.rcode.NOERROR

    answer_sig = response.get_rrset(
        section="ANSWER",
        name=qname,
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.RRSIG,
        covers=dns.rdatatype.A,
    )
    assert answer_sig is not None
    assert len(answer_sig) == 1
    rrsig = answer_sig[0]
    assert isinstance(rrsig, dns.rdtypes.ANY.RRSIG.RRSIG)
    # RRSIG labels field RFC 4034 section 3.1.3 does not count:
    # - root label
    # - leftmost * label
    wildcard_parent_labels = rrsig.labels + 1  # add root but not leftmost *
    assert wildcard_parent_labels < len(qname)

    # 1. We have RRSIG from the wildcard '*.something', which proves the node
    # 'something' exists (by definition - it has a child, so it exists, but
    # maybe it is an ENT). Thus we expect closest encloser = 'something'
    # 2. If wildcard synthesis is legitimate, QNAME itself and no nodes between
    # QNAME and the closest encloser can exist. Because of DNS node existence
    # rules it's sufficient to prove non-existence of next-closer name, i.e.
    # <one_label_under>.<closest_encloser>, to deny existence of the whole
    # subtree down to QNAME.

    ce, nce = ZONE.closest_encloser(qname)
    assert ce == qname.split(wildcard_parent_labels)[1]
    # ce is proven to exist by the RRSIG
    assert nce == qname.split(wildcard_parent_labels + 1)[1]
    # nce must be proven to NOT exist
    check_nsec3_covers(nce, response)
