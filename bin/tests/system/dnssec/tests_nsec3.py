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

from hypothesis import assume, given

from isctest.hypothesis.strategies import dns_names
import isctest

SUFFIX = dns.name.from_text("nsec3.example.")
AUTH = "10.53.0.3"
RESOLVER = "10.53.0.4"
TIMEOUT = 5


def get_known_names_and_delegations():

    # Read zone file
    system_test_root = Path(os.environ["srcdir"])
    with open(
        f"{system_test_root}/dnssec/ns3/nsec3.example.db.in", encoding="utf-8"
    ) as zf:
        content = dns.zone.from_file(zf, origin=SUFFIX, relativize=False)
    all_names = set(content)
    known_names = sorted(all_names)

    # Remove out of zone, obscured and glue names
    for known_name in known_names:
        relation, _, _ = known_name.fullcompare(SUFFIX)
        if relation == dns.name.NameRelation.EQUAL:
            continue
        if relation in (dns.name.NameRelation.NONE, dns.name.NameRelation.SUPERDOMAIN):
            known_names.remove(known_name)
            continue
        nsset = content.get_rdataset(known_name, rdtype=dns.rdatatype.NS)
        dname = content.get_rdataset(known_name, rdtype=dns.rdatatype.DNAME)
        if nsset is not None or dname is not None:
            for glue in known_names:
                relation, _, _ = glue.fullcompare(known_name)
                if relation == dns.name.NameRelation.SUBDOMAIN:
                    known_names.remove(glue)

    # Add in possible ENT names
    for known_name in known_names:
        _, super_name = known_name.split(len(known_name.labels) - 1)
        while len(super_name.labels) > len(SUFFIX.labels):
            known_names.append(super_name)
            _, super_name = super_name.split(len(super_name.labels) - 1)
    known_names = set(known_names)

    # Build list of delegation points and DNAMES
    delegations = []
    for known_name in known_names:
        relation, _, _ = known_name.fullcompare(SUFFIX)
        if relation == dns.name.NameRelation.EQUAL:
            continue
        nsset = content.get_rdataset(known_name, rdtype=dns.rdatatype.NS)
        dname = content.get_rdataset(known_name, rdtype=dns.rdatatype.DNAME)
        if nsset is not None or dname is not None:
            delegations.append(known_name)

    # build list of WILDCARD named
    wildcards = []
    for known_name in known_names:
        if known_name.is_wild():
            wildcards.append(known_name)
    return known_names, delegations, wildcards


KNOWN_NAMES, DELEGATIONS, WILDCARDS = get_known_names_and_delegations()


def is_delegated(name, delegations):
    for delegation in delegations:
        relation, _, _ = name.fullcompare(delegation)
        if relation in (dns.name.NameRelation.EQUAL, dns.name.NameRelation.SUBDOMAIN):
            return True
    return False


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
@given(name=dns_names(suffix=KNOWN_NAMES))
def test_dnssec_nsec3_subdomain_nxdomain(
    server, name: dns.name.Name, named_port: int
) -> None:
    noqname_test(server, name, named_port)


def noqname_test(server, name: dns.name.Name, named_port: int) -> None:
    # Name must not exist.
    assume(name not in KNOWN_NAMES)

    # Name must not be below a delegation or DNAME.
    assume(not is_delegated(name, DELEGATIONS))

    query = dns.message.make_query(
        name, dns.rdatatype.A, use_edns=True, want_dnssec=True
    )
    response = isctest.query.tcp(query, server, named_port, timeout=TIMEOUT)
    isctest.check.is_response_to(response, query)
    assert response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)

    # Retrieve closest encloser (ce) and next closest encloser (nce).
    ce = None
    nce = None
    if response.rcode() is dns.rcode.NOERROR:
        # this should only be a wild card response
        answer_sig = response.get_rrset(
            section="ANSWER",
            name=name,
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.RRSIG,
            covers=dns.rdatatype.A,
        )
        assert answer_sig is not None
        assert len(answer_sig) == 1
        # root label is not being counted in labels field, RFC 4034 section 3.1.3
        ce_labels = answer_sig[0].labels + 1
        # wildcard labels < QNAME labels
        assert ce_labels < len(name.labels)
        # ce is wildcard name w/o wildcard label
        _, ce = name.split(ce_labels)
        _, nce = name.split(ce_labels + 1)
    else:
        ce_labels = 0
        for zname in KNOWN_NAMES:
            relation, _, nlabels = name.fullcompare(zname)
            if relation == dns.name.NameRelation.SUBDOMAIN:
                if nlabels > ce_labels:
                    ce_labels = nlabels
                    ce = zname
                    _, nce = name.split(ce_labels + 1)
        assert ce is not None
        assert nce is not None

        # Response has closest encloser NSEC3.
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

    # Response has NSEC3 that covers the next closer name.
    check_nsec3_covers(nce, response)

    wc = dns.name.from_text("*", ce)
    if response.rcode() is dns.rcode.NOERROR:
        # only NOERRORs should be from wildcards
        found_wc = False
        for wildcard in WILDCARDS:
            if wildcard == wc:
                found_wc = True
        assert found_wc

    if response.rcode() == dns.rcode.NXDOMAIN:
        # Response has NSEC3 that covers the wildcard.
        check_nsec3_covers(wc, response)
