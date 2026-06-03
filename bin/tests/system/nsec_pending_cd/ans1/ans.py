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
from datetime import datetime, timedelta, timezone
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
PARENT = "tld.test."
ATTACKER = "attacker.tld.test."
VICTIM = "victim.tld.test."
VICTIM_A = "203.0.113.1"
POISON_NEXT = f"b.{VICTIM}"


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


def attacker_nsec_rrset() -> dns.rrset.RRset:
    return rrset(
        ATTACKER,
        dns.rdatatype.NSEC,
        f"{POISON_NEXT} NS SOA RRSIG NSEC DNSKEY",
    )


def garbage_rrsig(covered: dns.rrset.RRset, signer: Key) -> dns.rrset.RRset:
    now = datetime.now(timezone.utc)
    inception = (now - timedelta(hours=1)).strftime("%Y%m%d%H%M%S")
    expiration = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%S")
    signature = base64.b64encode(bytes(64)).decode("ascii")
    text = (
        f"{dns.rdatatype.to_text(covered.rdtype)} "
        f"{signer.dnskey.algorithm} 3 {covered.ttl} "
        f"{expiration} {inception} 9999 {PARENT} {signature}"
    )
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
    return dns.rrset.from_rdata(covered.name, covered.ttl, rdata)


def prepare_response(qctx: QueryContext) -> dns.message.Message:
    qctx.prepare_new_response(with_zone_data=False)
    qctx.response.flags |= dns.flags.AA
    qctx.response.set_rcode(dns.rcode.NOERROR)
    return qctx.response


class PendingNsecHandler(ResponseHandler):
    def __init__(self, key: Key) -> None:
        self.key = key
        self.parent = name(PARENT)
        self.attacker = name(ATTACKER)
        self.victim = name(VICTIM)

    def match(self, qctx: QueryContext) -> bool:
        return True

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
        elif qctx.qname == self.attacker and qctx.qtype == dns.rdatatype.NSEC:
            if qctx.query.flags & dns.flags.CD:
                nsec = attacker_nsec_rrset()
                response.answer.append(nsec)
                response.answer.append(garbage_rrsig(nsec, self.key))
            else:
                response.set_rcode(dns.rcode.REFUSED)
        elif qctx.qname == self.victim and qctx.qtype == dns.rdatatype.A:
            add_signed(
                response.answer,
                rrset(VICTIM, dns.rdatatype.A, VICTIM_A),
                self.key,
            )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
            add_signed(response.authority, soa_rrset(PARENT), self.key)

        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(PendingNsecHandler(load_key()))
    server.run()


if __name__ == "__main__":
    main()
