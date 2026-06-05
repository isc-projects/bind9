#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)

TTL = 300
ZONE = "f043.test."
QUERY = f"svc.{ZONE}"
VICTIM = f"victim.{ZONE}"
WILDCARD = f"*.{ZONE}"
FORGED_A = "198.51.100.90"
LEGIT_A = "192.0.2.50"


@dataclass(frozen=True)
class Key:
    zone: dns.name.Name
    private_key: object
    dnskey: dns.rdata.Rdata


def name(text: str) -> dns.name.Name:
    return dns.name.from_text(text)


def load_key() -> Key:
    path = Path(__file__).resolve().parent / "keys.json"
    with path.open(encoding="utf-8") as keys_file:
        raw_key = json.load(keys_file)[ZONE]

    private_key = serialization.load_pem_private_key(
        raw_key["private_pem"].encode("ascii"),
        password=None,
    )
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, raw_key["dnskey"]
    )
    return Key(name(ZONE), private_key, dnskey)


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


def soa_rrset() -> dns.rrset.RRset:
    return rrset(
        ZONE,
        dns.rdatatype.SOA,
        f"ns.{ZONE} hostmaster.{ZONE} 1 3600 600 86400 300",
    )


def add_dnskey(response: dns.message.Message, key: Key) -> None:
    add_signed(response.answer, rrset_from_rdata(ZONE, key.dnskey), key)


def wildcard_rrsig(owner: str, key: Key) -> dns.rrset.RRset:
    wildcard = rrset(WILDCARD, dns.rdatatype.A, FORGED_A)
    rrsig = dns.dnssec.sign(
        wildcard,
        key.private_key,
        key.zone,
        key.dnskey,
        lifetime=86400,
        verify=True,
    )
    return dns.rrset.from_rdata(name(owner), wildcard.ttl, rrsig)


def add_wildcard_a(section: list[dns.rrset.RRset], owner: str, key: Key) -> None:
    section.append(rrset(owner, dns.rdatatype.A, FORGED_A))
    section.append(wildcard_rrsig(owner, key))


class FromWildcardAdditionalHandler(ResponseHandler):
    def __init__(self, key: Key) -> None:
        self.key = key
        self.zone = name(ZONE)
        self.query = name(QUERY)
        self.victim = name(VICTIM)

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname.is_subdomain(self.zone)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.flags |= dns.flags.AA
        qctx.response.set_rcode(dns.rcode.NOERROR)

        if qctx.qname == self.zone and qctx.qtype == dns.rdatatype.DNSKEY:
            add_dnskey(qctx.response, self.key)
        elif qctx.qname == self.zone and qctx.qtype == dns.rdatatype.SOA:
            add_signed(qctx.response.answer, soa_rrset(), self.key)
        elif qctx.qname == self.query and qctx.qtype == dns.rdatatype.MX:
            add_signed(
                qctx.response.answer,
                rrset(QUERY, dns.rdatatype.MX, f"10 {VICTIM}"),
                self.key,
            )
            add_wildcard_a(qctx.response.additional, VICTIM, self.key)
        elif qctx.qname == self.victim and qctx.qtype == dns.rdatatype.A:
            add_signed(
                qctx.response.answer,
                rrset(VICTIM, dns.rdatatype.A, LEGIT_A),
                self.key,
            )
        else:
            add_signed(qctx.response.authority, soa_rrset(), self.key)

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(FromWildcardAdditionalHandler(load_key()))
    server.run()


if __name__ == "__main__":
    main()
