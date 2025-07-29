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

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional, Tuple

import pytest

pytest.importorskip("dns", minversion="2.5.0")
import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.ANY.NSEC3
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


def do_test_query(
    qname, qtype, server, named_port
) -> Tuple[dns.message.Message, "NSEC3Checker"]:
    query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
    response = isctest.query.tcp(query, server, named_port, timeout=TIMEOUT)
    isctest.check.is_response_to(response, query)
    assert response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
    return response, NSEC3Checker(response)


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


def check_wildcard_nodata(server, named_port: int, qname: dns.name.Name) -> None:
    response, nsec3check = do_test_query(qname, dns.rdatatype.AAAA, server, named_port)
    assert response.rcode() is dns.rcode.NOERROR

    ce, nce = ZONE.closest_encloser(qname)
    nsec3check.prove_name_exists(ce)
    nsec3check.prove_name_does_not_exist(nce)

    wname = ZONE.source_of_synthesis(qname)
    # expecting proof that wildcard owner does not have rdatatype requested
    nsec3check.prove_name_exists(wname)
    nsec3check.check_extraneous_rrs()


def check_nxdomain(server, named_port: int, qname: dns.name.Name) -> None:
    response, nsec3check = do_test_query(qname, dns.rdatatype.A, server, named_port)
    assert response.rcode() is dns.rcode.NXDOMAIN

    ce, nce = ZONE.closest_encloser(qname)
    nsec3check.prove_name_exists(ce)
    nsec3check.prove_name_does_not_exist(nce)

    wname = ZONE.source_of_synthesis(qname)
    nsec3check.prove_name_does_not_exist(wname)
    nsec3check.check_extraneous_rrs()


def check_wildcard_synthesis(server, named_port: int, qname: dns.name.Name) -> None:
    """Expect wildcard response with a signed A RRset"""
    response, nsec3check = do_test_query(qname, dns.rdatatype.A, server, named_port)
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
    nsec3check.prove_name_does_not_exist(nce)
    nsec3check.check_extraneous_rrs()


@dataclass(kw_only=True, frozen=True)
class NSEC3Params:
    """Common values from a single DNS response"""

    algorithm: int
    flags: int
    iterations: int
    salt: Optional[bytes]


class NSEC3Checker:
    def __init__(self, response: dns.message.Message):
        for rrset in response.answer:
            assert not rrset.match(
                dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
            ), f"unexpected NSEC3 RR in ANSWER section:\n{response}"
        for rrset in response.additional:
            assert not rrset.match(
                dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
            ), f"unexpected NSEC3 RR in ADDITIONAL section:\n{response}"

        attrs_seen = {
            "algorithm": None,
            "flags": None,
            "iterations": None,
            "salt": None,
        }
        first = True
        owners_seen = set()
        self.rrsets = []
        for rrset in response.authority:
            if not rrset.match(
                dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
            ):
                continue
            assert (
                rrset.name not in owners_seen
            ), f"duplicate NSEC3 owner {rrset.name}:\n{response}"
            owners_seen.add(rrset.name)

            assert len(rrset) == 1
            rr = rrset[0]
            assert isinstance(rr, dns.rdtypes.ANY.NSEC3.NSEC3)

            assert (
                "NSEC3"
                not in dns.rdtypes.ANY.NSEC3.Bitmap(rr.windows).to_text().split()
            ), f"NSEC3 RRset with NSEC3 in type bitmap:\n{response}"

            # NSEC3 parameters MUST be consistent across all NSEC3 RRs:
            # RFC 5155 section 7.2, last paragraph
            for attr_name, value_seen in attrs_seen.items():
                current = getattr(rr, attr_name)
                if first:
                    attrs_seen[attr_name] = current
                else:
                    assert (
                        current == value_seen
                    ), f"inconsistent {attr_name}\n{response}"
            first = False
            self.rrsets.append(rrset)

        assert attrs_seen["algorithm"] is not None, f"no NSEC3 found\n{response}"
        self.params = NSEC3Params(**attrs_seen)  # type: NSEC3Params
        self.response = response  # type: dns.message.Message
        self.owners_present = owners_seen
        self.owners_used = set()

    @staticmethod
    def nsec3_covers(rrset: dns.rrset.RRset, hashed_name: dns.name.Name) -> bool:
        """
        Test if 'hashed_name' is covered by an NSEC3 record in 'rrset', i.e. the name does not exist.
        """
        prev_name = rrset.name

        assert len(rrset) == 1
        nsec3 = rrset[0]
        assert isinstance(nsec3, dns.rdtypes.ANY.NSEC3.NSEC3)
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

    def hash_name(self, name: dns.name.Name) -> dns.name.Name:
        nhash = dns.dnssec.nsec3_hash(
            name,
            salt=self.params.salt,
            iterations=self.params.iterations,
            algorithm=self.params.algorithm,
        )
        return dns.name.from_text(nhash, SUFFIX)

    def prove_name_does_not_exist(self, name: dns.name.Name) -> dns.rrset.RRset:
        """Hash of a given name must fall between an NSEC3 owner and 'next' name"""
        hashed_name = self.hash_name(name)
        for rrset in self.rrsets:
            name_is_covered = self.nsec3_covers(rrset, hashed_name)
            if name_is_covered:
                self.owners_used.add(rrset.name)
                return rrset

        assert (
            False
        ), f"Expected covering NSEC3 for {name} (hash={hashed_name}) not found:\n{self.response}"

    def prove_name_exists(self, owner: dns.name.Name) -> dns.rrset.RRset:
        """Check response has NSEC3 RR matching given owner name, i.e. the name exists."""
        nsec3_owner = self.hash_name(owner)
        for rrset in self.rrsets:
            if rrset.match(
                nsec3_owner, dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
            ):
                self.owners_used.add(rrset.name)
                return rrset
        assert (
            False
        ), f"Expected matching NSEC3 for {owner} (hash={nsec3_owner}) not found:\n{self.response}"

    def check_extraneous_rrs(self):
        """Check that all NSEC3 RRs present in the message were actually needed for proofs"""
        assert (
            self.owners_used == self.owners_present
        ), f"extraneous NSEC3 RRs detected\n{self.response}"
