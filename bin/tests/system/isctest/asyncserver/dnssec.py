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

from dataclasses import dataclass
from typing import ClassVar, final

import abc
import bisect
import functools

import dns.dnssec
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

import isctest.zone


@dataclass(frozen=True)
class SigningKey:
    zone: dns.name.Name
    dnskey: dns.rrset.RRset
    private_key: isctest.zone.PrivateKey


class NonExistenceException(Exception):
    pass


@dataclass(frozen=True)
class NonExistenceProver(abc.ABC):
    """
    Base class for NSEC/NSEC3 implementations that add RRsets required by the
    relevant RFCs to negative DNS responses created from zone data.
    """

    zone: dns.zone.Zone
    qname: dns.name.Name
    qclass: dns.rdataclass.RdataClass
    response: dns.message.Message

    proof_rdatatype: ClassVar[dns.rdatatype.RdataType]
    _provers: ClassVar[dict[dns.rdatatype.RdataType, type["NonExistenceProver"]]] = {}

    def __init_subclass__(cls) -> None:
        assert cls.proof_rdatatype not in cls._provers
        cls._provers[cls.proof_rdatatype] = cls

    @classmethod
    def for_query(
        cls,
        zone: dns.zone.Zone,
        qname: dns.name.Name,
        qclass: dns.rdataclass.RdataClass,
        response: dns.message.Message,
    ) -> "NonExistenceProver":
        for proof_rdatatype, prover_class in cls._provers.items():
            if next(zone.iterate_rdatasets(proof_rdatatype), None):
                return prover_class(zone, qname, qclass, response)

        raise RuntimeError(
            "Non-existence proof requested for a zone with no NSEC(3) records"
        )

    @abc.abstractmethod
    def prove_no_ds(self, name: dns.name.Name) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def prove_ent(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def prove_nxdomain(self) -> None:
        raise NotImplementedError

    def prove_nodata(self) -> None:
        if self.zone.get_node(self.qname):
            self._prove_nodata_no_wildcard()
            return

        self._prove_nodata_wildcard()

    @abc.abstractmethod
    def _prove_nodata_no_wildcard(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def _prove_nodata_wildcard(self) -> None:
        raise NotImplementedError

    def prove_noerror(self) -> None:
        if self.zone.get_node(self.qname):
            return

        self._prove_noerror_wildcard()

    @abc.abstractmethod
    def _prove_noerror_wildcard(self) -> None:
        raise NotImplementedError

    def _get_closest_encloser(
        self, name: dns.name.Name
    ) -> tuple[dns.name.Name, dns.name.Name]:
        names = [name, name.parent()]
        while not self._is_usable_encloser(names[-1]):
            names.append(names[-1].parent())

        return names[-1], names[-2]

    @abc.abstractmethod
    def _is_usable_encloser(self, name: dns.name.Name) -> bool:
        raise NotImplementedError

    @property
    def _wildcard_for_closest_encloser(self) -> dns.name.Name:
        closest_encloser_name, _ = self._get_closest_encloser(self.qname)
        return dns.name.from_text("*", origin=closest_encloser_name)

    @functools.cached_property
    def _chain(self) -> tuple[dns.name.Name, ...]:
        proof_rdatasets = self.zone.iterate_rdatasets(self.proof_rdatatype)
        return tuple(sorted(n for n, _ in proof_rdatasets))

    def _add_chain_element_matching(self, name: dns.name.Name) -> None:
        self._add_rrset_with_rrsig(name)

    def _add_chain_element_covering(self, name: dns.name.Name) -> None:
        index = bisect.bisect_left(self._chain, name)
        self._add_rrset_with_rrsig(self._chain[index - 1])

    def _add_rrset_with_rrsig(self, owner: dns.name.Name) -> None:
        node = self.zone.get_node(owner)
        assert node

        rdataset = node.get_rdataset(self.qclass, self.proof_rdatatype)
        rrset = dns.rrset.RRset(owner, self.qclass, self.proof_rdatatype)
        rrset.update(rdataset)

        sigrdataset = node.get_rdataset(
            self.qclass, dns.rdatatype.RRSIG, self.proof_rdatatype
        )
        assert sigrdataset
        rrsig = dns.rrset.RRset(
            owner, self.qclass, dns.rdatatype.RRSIG, self.proof_rdatatype
        )
        rrsig.update(sigrdataset)

        if rrset not in self.response.authority:
            self.response.authority.append(rrset)
            self.response.authority.append(rrsig)


@final
class NsecNonExistenceProver(NonExistenceProver):

    proof_rdatatype = dns.rdatatype.NSEC

    def prove_no_ds(self, name: dns.name.Name) -> None:
        self._add_nsec_matching(name)

    def prove_ent(self) -> None:
        self._add_nsec_covering(self.qname)

    def prove_nxdomain(self) -> None:
        self._add_nsec_covering(self.qname)
        self._add_nsec_covering(self._wildcard_for_closest_encloser)

    def _prove_nodata_no_wildcard(self) -> None:
        self._add_nsec_matching(self.qname)

    def _prove_nodata_wildcard(self) -> None:
        self._add_nsec_covering(self.qname)
        self._add_nsec_matching(self._wildcard_for_closest_encloser)

    def _prove_noerror_wildcard(self) -> None:
        self._add_nsec_covering(self.qname)

    def _add_nsec_matching(self, name: dns.name.Name) -> None:
        if name not in self._chain:
            raise NonExistenceException("Expected NSEC record not found")
        self._add_chain_element_matching(name)

    def _add_nsec_covering(self, name: dns.name.Name) -> None:
        if name in self._chain:
            raise NonExistenceException("Unexpected NSEC record found")
        self._add_chain_element_covering(name)

    def _is_usable_encloser(self, name: dns.name.Name) -> bool:
        return any(n.is_subdomain(name) for n in self.zone.nodes)


@final
class Nsec3NonExistenceProver(NonExistenceProver):

    proof_rdatatype = dns.rdatatype.NSEC3

    def prove_no_ds(self, name: dns.name.Name) -> None:
        self._add_nsec3_matching_or_closest_encloser_proof(name)

    def prove_ent(self) -> None:
        self._add_nsec3_matching_or_closest_encloser_proof(self.qname)

    def prove_nxdomain(self) -> None:
        self._add_closest_encloser_proof(self.qname)
        self._add_nsec3_covering(self._wildcard_for_closest_encloser)

    def _prove_nodata_no_wildcard(self) -> None:
        self._add_nsec3_matching_or_closest_encloser_proof(self.qname)

    def _prove_nodata_wildcard(self) -> None:
        self._add_closest_encloser_proof(self.qname)
        self._add_nsec3_matching(self._wildcard_for_closest_encloser)

    def _prove_noerror_wildcard(self) -> None:
        self._add_closest_encloser_proof(self.qname)

    def _get_nsec3_owner(self, name: dns.name.Name) -> dns.name.Name:
        assert self.zone.origin

        nsec3param = self.zone.get_rdataset(self.zone.origin, dns.rdatatype.NSEC3PARAM)
        assert nsec3param

        nsec3_hash = dns.dnssec.nsec3_hash(
            name,
            nsec3param[0].salt,
            nsec3param[0].iterations,
            nsec3param[0].algorithm,
        )
        return dns.name.from_text(nsec3_hash, origin=self.zone.origin)

    def _add_nsec3_matching(self, name: dns.name.Name) -> None:
        nsec3_owner = self._get_nsec3_owner(name)
        if nsec3_owner not in self._chain:
            raise NonExistenceException("Matching NSEC3 record not found")
        self._add_chain_element_matching(nsec3_owner)

    def _add_nsec3_covering(self, name: dns.name.Name) -> None:
        nsec3_owner = self._get_nsec3_owner(name)
        if nsec3_owner in self._chain:
            raise NonExistenceException(
                "Expected a covering NSEC3 record, got a matching one"
            )
        self._add_chain_element_covering(nsec3_owner)

    def _add_closest_encloser_proof(self, name: dns.name.Name) -> None:
        closest_encloser_name, next_closer_name = self._get_closest_encloser(name)
        self._add_nsec3_matching(closest_encloser_name)
        self._add_nsec3_covering(next_closer_name)

    def _add_nsec3_matching_or_closest_encloser_proof(
        self, name: dns.name.Name
    ) -> None:
        try:
            # No Opt-Out
            self._add_nsec3_matching(name)
        except NonExistenceException:
            # Opt-Out
            self._add_closest_encloser_proof(name)

    def _is_usable_encloser(self, name: dns.name.Name) -> bool:
        return self._get_nsec3_owner(name) in self._chain
