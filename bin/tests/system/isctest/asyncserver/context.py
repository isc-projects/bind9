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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import copy
import datetime
import enum

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone

from .dnssec import NonExistenceProver, SigningKey


class DnsProtocol(enum.Enum):
    UDP = enum.auto()
    TCP = enum.auto()


@dataclass(frozen=True)
class Peer:
    """
    Pretty-printed connection endpoint.
    """

    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass
class QueryContext:
    """
    Context for the incoming query which may be used for preparing the response.
    """

    query: dns.message.Message
    response: dns.message.Message
    zones: Mapping[dns.name.Name, dns.zone.Zone]
    keys: Mapping[dns.name.Name, Sequence[SigningKey]]
    socket: Peer
    peer: Peer
    protocol: DnsProtocol
    zone: dns.zone.Zone | None = field(default=None, init=False)
    soa: dns.rrset.RRset | None = field(default=None, init=False)
    node: dns.node.Node | None = field(default=None, init=False)
    answer: dns.rdataset.Rdataset | None = field(default=None, init=False)
    alias: dns.name.Name | None = field(default=None, init=False)
    _initialized_response: dns.message.Message | None = field(default=None, init=False)
    _initialized_response_with_zone_data: dns.message.Message | None = field(
        default=None, init=False
    )

    @property
    def qname(self) -> dns.name.Name:
        return self.query.question[0].name

    @property
    def current_qname(self) -> dns.name.Name:
        return self.alias or self.qname

    @property
    def qclass(self) -> dns.rdataclass.RdataClass:
        return self.query.question[0].rdclass

    @property
    def qtype(self) -> dns.rdatatype.RdataType:
        return self.query.question[0].rdtype

    def prepare_new_response(
        self, /, with_zone_data: bool = True
    ) -> dns.message.Message:
        if with_zone_data:
            assert self._initialized_response_with_zone_data
            self.response = copy.deepcopy(self._initialized_response_with_zone_data)
        else:
            assert self._initialized_response
            self.response = copy.deepcopy(self._initialized_response)
        return self.response

    def save_initialized_response(self, /, with_zone_data: bool) -> None:
        if with_zone_data:
            self._initialized_response_with_zone_data = copy.deepcopy(self.response)
        else:
            self._initialized_response = copy.deepcopy(self.response)

    def get_rrsig(
        self, rrset: dns.rrset.RRset, /, node: dns.node.Node | None = None
    ) -> dns.rrset.RRset | None:
        if not self.query.ednsflags & dns.flags.DO:
            return None

        assert self.zone
        assert self.zone.origin

        if node is None:
            node = (
                self.node
                if rrset.rdtype != dns.rdatatype.SOA
                else self.zone.get_node(self.zone.origin)
            )
        assert node

        rrsig_rdataset = node.get_rdataset(
            self.qclass, dns.rdatatype.RRSIG, rrset.rdtype
        )
        if not rrsig_rdataset:
            return None

        rrsig_rrset = dns.rrset.RRset(rrset.name, self.qclass, dns.rdatatype.RRSIG)
        rrsig_rrset.update(rrsig_rdataset)
        return rrsig_rrset

    def sign(
        self,
        signed: dns.rrset.RRset,
        /,
        key: SigningKey | None = None,
        bogus: bool = False,
    ) -> dns.rrset.RRset:
        assert self.zone
        assert self.zone.origin

        if not key:
            keys = self.keys.get(self.zone.origin)
            assert keys
            key = keys[0]

        one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
        signature = dns.dnssec.sign(
            signed,
            key.private_key,
            key.zone,
            key.dnskey[0],
            inception=one_hour_ago,
            lifetime=86400,
        )

        rdata: dns.rdata.Rdata = signature

        if bogus:
            rdata = signature.replace(signature=bytes(len(signature.signature)))

        return dns.rrset.from_rdata(signed.name, signed.ttl, rdata)

    @property
    def nsecx(self) -> "NonExistenceProver":
        if not self.zone:
            raise RuntimeError(
                "Non-existence proof requested for a query context that did not match any zone"
            )

        return NonExistenceProver.for_query(
            self.zone, self.current_qname, self.qclass, self.response
        )
