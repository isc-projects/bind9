#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import base64
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

TTL = 300
PARENT = "p025.test."
CHILD = f"evil.{PARENT}"
PARENT_NS = f"ns.{PARENT}"
CHILD_NS = f"ns.{CHILD}"
CLOSEST = f"victim2.{CHILD}"
ATTACK = f"b.{CLOSEST}"
LEGIT = f"legit.{CHILD}"
WILDCARD = f"*.{CHILD}"
FORGED_A = "6.6.6.6"


@dataclass(frozen=True)
class Key:
    zone: dns.name.Name
    private_key: object
    dnskey: dns.rdata.Rdata
    ds: dns.rdata.Rdata


@dataclass(frozen=True)
class Nsec3Entry:
    owner: str
    owner_hash: str
    types: tuple[str, ...]


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
        f"ns.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def nsec3_hash(owner: str) -> str:
    return dns.dnssec.nsec3_hash(owner, salt=None, iterations=0, algorithm=1).upper()


def base32hex_add(hash_text: str, delta: int) -> str:
    raw = bytearray(base64.b32hexdecode(hash_text.upper()))
    value = int.from_bytes(raw, "big") + delta
    value %= 1 << (8 * len(raw))
    return base64.b32hexencode(value.to_bytes(len(raw), "big")).decode("ascii")


def nsec3_rrset(
    zone: str, owner_hash: str, next_hash: str, *types: str
) -> dns.rrset.RRset:
    return rrset(
        f"{owner_hash}.{zone}",
        dns.rdatatype.NSEC3,
        f"1 0 0 - {next_hash} {' '.join(types)}",
    )


class Nsec3Chain:
    def __init__(self, zone: str, entries: list[tuple[str, tuple[str, ...]]]) -> None:
        self.zone = zone
        self.entries = sorted(
            [Nsec3Entry(owner, nsec3_hash(owner), types) for owner, types in entries],
            key=lambda entry: entry.owner_hash,
        )

    def rrset_for_entry(self, entry: Nsec3Entry) -> dns.rrset.RRset:
        index = self.entries.index(entry)
        next_hash = self.entries[(index + 1) % len(self.entries)].owner_hash
        return nsec3_rrset(self.zone, entry.owner_hash, next_hash, *entry.types)

    def rrsets(self) -> list[dns.rrset.RRset]:
        return [self.rrset_for_entry(entry) for entry in self.entries]


def add_nsec3_chain(
    section: list[dns.rrset.RRset], chain: Nsec3Chain, signer: Key
) -> None:
    for covered in chain.rrsets():
        add_signed(section, covered, signer)


def add_tight_parent_nsec3(section: list[dns.rrset.RRset], parent: Key) -> None:
    target_hash = nsec3_hash(f"{CLOSEST}")
    covered = nsec3_rrset(
        PARENT,
        base32hex_add(target_hash, -1),
        base32hex_add(target_hash, 1),
        "TXT",
        "RRSIG",
    )
    add_signed(section, covered, parent)


def wildcard_rrsig(owner: str, child: Key) -> dns.rrset.RRset:
    wildcard = rrset(WILDCARD, dns.rdatatype.A, FORGED_A)
    rrsig = dns.dnssec.sign(
        wildcard,
        child.private_key,
        child.zone,
        child.dnskey,
        lifetime=86400,
        verify=True,
    )
    return dns.rrset.from_rdata(name(owner), wildcard.ttl, rrsig)


def add_wildcard_answer(response: dns.message.Message, owner: str, child: Key) -> None:
    response.answer.append(rrset(owner, dns.rdatatype.A, FORGED_A))
    response.answer.append(wildcard_rrsig(owner, child))


class WrongZoneNsec3Handler(ResponseHandler):
    def __init__(self, keys: dict[str, Key]) -> None:
        self.keys = keys
        self.parent = name(PARENT)
        self.child = name(CHILD)
        self.parent_ns = name(PARENT_NS)
        self.child_ns = name(CHILD_NS)
        self.child_nsec3 = Nsec3Chain(
            CHILD,
            [
                (CHILD, ("NS", "SOA", "RRSIG", "DNSKEY", "NSEC3PARAM")),
                (WILDCARD, ("A", "RRSIG")),
                (CHILD_NS, ("A", "RRSIG")),
            ],
        )

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname.is_subdomain(self.parent)

    def _add_extra_nsec3(self, response: dns.message.Message, qname: str) -> None:
        parent_key = self.keys[PARENT]
        child_key = self.keys[CHILD]
        if "victim2." in qname:
            add_tight_parent_nsec3(response.authority, parent_key)
        else:
            add_nsec3_chain(response.authority, self.child_nsec3, child_key)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.flags |= dns.flags.AA
        qctx.response.set_rcode(dns.rcode.NOERROR)

        parent_key = self.keys[PARENT]
        child_key = self.keys[CHILD]
        qname = qctx.qname.to_text()

        if qctx.qname == self.parent and qctx.qtype == dns.rdatatype.DNSKEY:
            # Priming, parent DNSKEY
            add_signed(
                qctx.response.answer,
                rrset_from_rdata(PARENT, parent_key.dnskey),
                parent_key,
            )
        elif qctx.qname == self.parent and qctx.qtype == dns.rdatatype.SOA:
            # Priming, parent SOA
            add_signed(qctx.response.answer, soa_rrset(PARENT), parent_key)
        elif qctx.qname == self.parent and qctx.qtype == dns.rdatatype.NS:
            # Priming, parent NS
            add_signed(
                qctx.response.answer,
                rrset(PARENT, dns.rdatatype.NS, PARENT_NS),
                parent_key,
            )
        elif qctx.qname == self.parent_ns and qctx.qtype == dns.rdatatype.A:
            # Priming, parent glue
            add_signed(
                qctx.response.answer,
                rrset(PARENT_NS, dns.rdatatype.A, "10.53.0.1"),
                parent_key,
            )
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.DS:
            # Priming, child DS
            add_signed(
                qctx.response.answer,
                rrset_from_rdata(CHILD, child_key.ds),
                parent_key,
            )
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.DNSKEY:
            # Priming, child DNSKEY
            add_signed(
                qctx.response.answer,
                rrset_from_rdata(CHILD, child_key.dnskey),
                child_key,
            )
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.SOA:
            # Priming, child SOA
            add_signed(qctx.response.answer, soa_rrset(CHILD), child_key)
        elif qctx.qname == self.child and qctx.qtype == dns.rdatatype.NS:
            # Priming, child NS
            add_signed(
                qctx.response.answer,
                rrset(CHILD, dns.rdatatype.NS, CHILD_NS),
                child_key,
            )
        elif qctx.qname == self.child_ns and qctx.qtype == dns.rdatatype.A:
            # Priming, child glue
            add_signed(
                qctx.response.answer,
                rrset(CHILD_NS, dns.rdatatype.A, "10.53.0.1"),
                child_key,
            )
        elif qctx.qname.is_subdomain(self.child):
            if qctx.qtype == dns.rdatatype.A:
                add_wildcard_answer(qctx.response, qname, child_key)
            else:
                add_signed(qctx.response.authority, soa_rrset(CHILD), child_key)
            # Adding malicious NSEC3
            self._add_extra_nsec3(qctx.response, qname)
        else:
            # Everything else is NODATA
            add_signed(qctx.response.authority, soa_rrset(PARENT), parent_key)

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(WrongZoneNsec3Handler(load_keys()))
    server.run()


if __name__ == "__main__":
    main()
