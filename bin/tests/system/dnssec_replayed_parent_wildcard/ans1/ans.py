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

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)

# P3: A signed zone P, chained to a configured trust anchor, that
# (a) publishes a wildcard *.P A or AAAA record and
# (b) delegates at least one separately-signed child C.P (own DS in P)
#     operated by a distinct principal.
TTL = 300
PARENT = "parent.hack."
CHILD = f"child.{PARENT}"
QUERY = f"q.{PARENT}"
SERVICE = f"svc.{CHILD}"
WILDCARD = f"*.{PARENT}"

FORGED_A = "198.51.100.45"
LEGIT_A = "192.0.2.113"


@dataclass(frozen=True)
class Key:
    zone: dns.name.Name
    private_key: object
    dnskey: dns.rdata.Rdata
    ds: dns.rdata.Rdata


def name(text: str) -> dns.name.Name:
    return dns.name.from_text(text)


def load_keys() -> dict[str, Key]:
    path = Path(__file__).resolve().parent / "keys.json"
    with path.open(encoding="utf-8") as keys_file:
        raw_keys = json.load(keys_file)

    keys = {}
    for zone, raw_key in raw_keys.items():
        private_key = serialization.load_pem_private_key(
            raw_key["private_pem"].encode("ascii"),
            password=None,
        )
        dnskey = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.DNSKEY, raw_key["dnskey"]
        )
        ds = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, raw_key["ds"])
        keys[zone] = Key(name(zone), private_key, dnskey, ds)

    return keys


def rrset(owner: str, rdtype: dns.rdatatype.RdataType, *rdatas: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, TTL, dns.rdataclass.IN, rdtype, *rdatas)


def rrset_from_rdata(owner: str, rdata: dns.rdata.Rdata) -> dns.rrset.RRset:
    return dns.rrset.from_rdata(name(owner), TTL, rdata)


def add_signed(
    section: list[dns.rrset.RRset], covered: dns.rrset.RRset, signer: Key
) -> None:
    rrsig = dns.dnssec.sign(
        covered,
        signer.private_key,
        signer.zone,
        signer.dnskey,
        lifetime=86400,
        verify=True,
    )
    section.append(covered)
    section.append(dns.rrset.from_rdata(covered.name, covered.ttl, rrsig))


def soa_rrset(zone: str) -> dns.rrset.RRset:
    return rrset(
        zone,
        dns.rdatatype.SOA,
        f"ns1.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def add_dnskey(response: dns.message.Message, zone: str, key: Key) -> None:
    add_signed(response.answer, rrset_from_rdata(zone, key.dnskey), key)


def add_ds(response: dns.message.Message, zone: str, child: Key, parent: Key) -> None:
    add_signed(response.answer, rrset_from_rdata(zone, child.ds), parent)


def add_nodata(response: dns.message.Message, zone: str, key: Key) -> None:
    add_signed(response.authority, soa_rrset(zone), key)


def wildcard_rrsig(owner: str, parent: Key) -> dns.rrset.RRset:
    wildcard = rrset(WILDCARD, dns.rdatatype.A, FORGED_A)
    rrsig = dns.dnssec.sign(
        wildcard,
        parent.private_key,
        parent.zone,
        parent.dnskey,
        lifetime=86400,
        verify=True,
    )
    return dns.rrset.from_rdata(name(owner), wildcard.ttl, rrsig)


def add_parent_mx_with_forged_additional(
    response: dns.message.Message, parent: Key
) -> None:
    add_signed(
        response.answer,
        rrset(QUERY, dns.rdatatype.MX, f"10 {SERVICE}"),
        parent,
    )
    response.additional.append(rrset(SERVICE, dns.rdatatype.A, FORGED_A))
    response.additional.append(wildcard_rrsig(SERVICE, parent))


def add_child_a(response: dns.message.Message, child: Key) -> None:
    add_signed(response.answer, rrset(SERVICE, dns.rdatatype.A, LEGIT_A), child)


class QueryCParentWildcardHandler(ResponseHandler):
    def __init__(self, keys: dict[str, Key]) -> None:
        self.keys = keys
        self.parent = name(PARENT)
        self.child = name(CHILD)
        self.query = name(QUERY)
        self.service = name(SERVICE)

    def match(self, qctx: QueryContext) -> bool:
        return True

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.flags |= dns.flags.AA
        qctx.response.set_rcode(dns.rcode.NOERROR)

        parent_key = self.keys[PARENT]
        child_key = self.keys[CHILD]

        if qctx.qname == self.parent and qctx.qtype == dns.rdatatype.DNSKEY:
            # Priming, DNSKEY RRset
            add_dnskey(qctx.response, PARENT, parent_key)
        elif qctx.qname == self.parent and qctx.qtype == dns.rdatatype.SOA:
            # Priming, SOA RRset
            add_signed(qctx.response.answer, soa_rrset(PARENT), parent_key)
        elif qctx.qname == self.query and qctx.qtype == dns.rdatatype.MX:
            # Trigger query.
            add_parent_mx_with_forged_additional(qctx.response, parent_key)
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.DS:
            # Chain of trust, DS of child.
            add_ds(qctx.response, CHILD, child_key, parent_key)
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.DNSKEY:
            # Chain of trust, DNSKEY of child.
            add_dnskey(qctx.response, CHILD, child_key)
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.SOA:
            # SOA of child.
            add_signed(qctx.response.answer, soa_rrset(CHILD), child_key)
        elif qctx.qname == self.service and qctx.qtype == dns.rdatatype.A:
            # Zone data at child.
            add_child_a(qctx.response, child_key)
        elif qctx.qname.is_subdomain(self.child):
            # No data at child.
            add_nodata(qctx.response, CHILD, child_key)
        elif qctx.qname.is_subdomain(self.parent):
            # No data at parent.
            add_nodata(qctx.response, PARENT, parent_key)
        else:
            qctx.response.set_rcode(dns.rcode.NXDOMAIN)

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    keys = load_keys()
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(QueryCParentWildcardHandler(keys))
    server.run()


if __name__ == "__main__":
    main()
