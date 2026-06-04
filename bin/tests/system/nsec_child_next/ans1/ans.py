#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import base64
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
PARENT = "p.test."
EVIL = "evil.p.test."
POISON = f"0.{EVIL}"
POISON_NEXT = "zzz.p.test."
TARGET = f"target.{PARENT}"
TARGET_A = "192.0.2.77"


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
        raw_key = json.load(keys_file)[PARENT]

    private_key = serialization.load_pem_private_key(
        raw_key["private_pem"].encode("ascii"),
        password=None,
    )
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, raw_key["dnskey"]
    )
    return Key(name(PARENT), private_key, dnskey)


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
        f"ns.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def nsec_rrset(owner: str, next_name: str, *types: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NSEC, f"{next_name} {' '.join(types)}")


def parent_apex_nsec() -> dns.rrset.RRset:
    return nsec_rrset(PARENT, EVIL, "NS", "SOA", "RRSIG", "NSEC", "DNSKEY")


def evil_delegation_nsec() -> dns.rrset.RRset:
    return nsec_rrset(EVIL, f"ns.{PARENT}", "NS", "RRSIG", "NSEC")


def malicious_nsec() -> dns.rrset.RRset:
    return nsec_rrset(POISON, POISON_NEXT, "A", "RRSIG", "NSEC")


def garbage_rrsig(covered: dns.rrset.RRset) -> dns.rrset.RRset:
    now = datetime.now(timezone.utc)
    inception = (now - timedelta(hours=1)).strftime("%Y%m%d%H%M%S")
    expiration = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%S")
    signature = base64.b64encode(bytes(64)).decode("ascii")
    labels = len(covered.name.labels) - 1
    text = (
        f"{dns.rdatatype.to_text(covered.rdtype)} "
        f"13 {labels} {covered.ttl} {expiration} {inception} "
        f"12345 {PARENT} {signature}"
    )
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
    return dns.rrset.from_rdata(covered.name, covered.ttl, rdata)


def prepare_response(qctx: QueryContext) -> dns.message.Message:
    qctx.prepare_new_response(with_zone_data=False)
    qctx.response.flags |= dns.flags.AA
    qctx.response.set_rcode(dns.rcode.NOERROR)
    return qctx.response


def add_parent_denial(
    response: dns.message.Message, signer: Key, nsec: dns.rrset.RRset
) -> None:
    add_signed(response.authority, soa_rrset(PARENT), signer)
    add_signed(response.authority, nsec, signer)


class InsecureNsecNextHandler(ResponseHandler):
    def __init__(self, key: Key) -> None:
        self.key = key
        self.parent = name(PARENT)
        self.evil = name(EVIL)
        self.poison = name(POISON)
        self.target = name(TARGET)

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname.is_subdomain(self.parent)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = prepare_response(qctx)

        if qctx.qname == self.parent and qctx.qtype == dns.rdatatype.DNSKEY:
            add_signed(
                response.answer,
                rrset_from_rdata(PARENT, self.key.dnskey),
                self.key,
            )
        elif qctx.qname == self.parent and qctx.qtype == dns.rdatatype.SOA:
            add_signed(response.answer, soa_rrset(PARENT), self.key)
        elif qctx.qname == self.parent and qctx.qtype == dns.rdatatype.NSEC:
            add_signed(response.answer, parent_apex_nsec(), self.key)
        elif qctx.qname == self.evil and qctx.qtype == dns.rdatatype.DS:
            add_parent_denial(response, self.key, evil_delegation_nsec())
        elif qctx.qname == self.poison and qctx.qtype == dns.rdatatype.NSEC:
            nsec = malicious_nsec()
            response.answer.append(nsec)
            response.answer.append(garbage_rrsig(nsec))
        elif qctx.qname == self.target and qctx.qtype == dns.rdatatype.A:
            add_signed(
                response.answer,
                rrset(TARGET, dns.rdatatype.A, TARGET_A),
                self.key,
            )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
            add_parent_denial(response, self.key, parent_apex_nsec())

        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(InsecureNsecNextHandler(load_key()))
    server.run()


if __name__ == "__main__":
    main()
