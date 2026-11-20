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

from collections.abc import AsyncGenerator

import abc

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.handlers import StaticResponseHandler
from isctest.asyncserver.matchers import Qname, Qtype

MAX_VALIDATIONS_PER_FETCH = 16


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def a(owner: str | dns.name.Name, address: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, address)


def nsec(owner: str | dns.name.Name, next_name: str, types: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NSEC, f"{next_name} {types}")


def nsec3(
    owner: str | dns.name.Name,
    next_hash: str,
    salt: bytes | None = None,
    iterations: int = 0,
) -> dns.rrset.RRset:
    return rrset(
        owner,
        dns.rdatatype.NSEC3,
        f"1 0 {iterations} {salt.hex() if salt else '-'} {next_hash} NS",
    )


class ChildNsHandler(StaticResponseHandler):
    matcher = Qname("c.p031.test") & Qtype(dns.rdatatype.NS)
    rcode = dns.rcode.NXDOMAIN


class GrandchildAHandler(ResponseHandler):
    """
    This handler imitates successfully spoofing unsigned responses to A queries
    sent to a server authoritative for an NSEC(3)-signed grandchild zone.  The
    subsequent validation-related queries are handled by subclasses of
    SpoofedNsecHandler, which intend to trick the validator into treating the
    grandchild zones as unsigned ones by signing forged NSEC(3) records with
    the grandparent zone's signing key.
    """

    matcher = Qname(
        "www-bind.grand.c.p031.test.",
        "www2-bind.grand.c.p031.test.",
        "www-bind.grand-dummy-first.c.p031.test.",
        "www2-bind.grand-dummy-first.c.p031.test.",
        "www-bind.grand-dummy-last.c.p031.test.",
        "www-bind.grand-too-many.c.p031.test.",
        "www-bind.grand-almost-too-many.c.p031.test.",
        "www-bind.grand3.c.p031.test.",
        "www-bind.grandsib.c.p031.test.",
    ) & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.answer.append(a(qctx.qname, "6.6.6.60"))
        yield DnsResponseSend(qctx.response)


class SpoofedNsecHandler(ResponseHandler, abc.ABC):
    """
    This handler imitates successfully spoofing a response to a DS query for a
    signed grandchild domain; the spoofed response is a negative one,
    containing an NSEC(3) record correctly signed by the grandparent's signing
    key; it "proves" the nonexistence of the grandchild's DS record in the
    grandparent zone.  A vulnerable resolver treats such a response as
    sufficient to prove that the grandchild zone is an insecure one.
    """

    qname: str

    def __init__(self) -> None:
        self.matcher = Qname(self.qname) & Qtype(dns.rdatatype.DS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)

        grandparent_origin = qctx.qname.parent().parent()
        qctx.zone = qctx.zones[grandparent_origin]

        assert qctx.zone
        assert qctx.zone.origin
        soa_rrset = qctx.zone.get_rrset(qctx.zone.origin, dns.rdatatype.SOA)
        assert soa_rrset
        if soa_rrsig := qctx.get_rrsig(soa_rrset):
            qctx.response.authority.append(soa_rrset)
            qctx.response.authority.append(soa_rrsig)

        qctx.response.authority.append(self.spoofed_rrset)
        genuine_rrsig = qctx.sign(self.spoofed_rrset)

        for rrsig_rdata in self.rrsigs(genuine_rrsig[0]):
            rrsig = dns.rrset.from_rdata(
                genuine_rrsig.name, genuine_rrsig.ttl, rrsig_rdata
            )
            qctx.response.authority.append(rrsig)

        yield DnsResponseSend(qctx.response)

    @property
    @abc.abstractmethod
    def spoofed_rrset(self) -> dns.rrset.RRset:
        raise NotImplementedError

    def rrsigs(self, genuine: dns.rdata.Rdata) -> list[dns.rdata.Rdata]:
        """
        The RRSIGs to send for the spoofed record, in wire order.
        """
        return [genuine]


class GrandchildDsNsecHandler(SpoofedNsecHandler):
    qname = "grand.c.p031.test."

    @property
    def spoofed_rrset(self) -> dns.rrset.RRset:
        return nsec(self.qname, "grandz.c.p031.test.", "NS RRSIG NSEC")


class GrandchildDsNsec3Handler(SpoofedNsecHandler):
    qname = "grand3.c.p031.test."

    @property
    def spoofed_rrset(self) -> dns.rrset.RRset:
        qname = dns.name.from_text(self.qname)
        nsec3_hash = dns.dnssec.nsec3_hash(qname, None, 0, 1)
        nsec3_owner = dns.name.from_text(nsec3_hash, origin=qname.parent().parent())
        return nsec3(nsec3_owner, nsec3_hash)


class GrandsiblingDsHandler(ResponseHandler):
    """
    This handler imitates successfully spoofing a response to a DS query for a
    signed grandchild domain ("grandsib.c.p031.test."); the spoofed response is
    one replayed from the child zone ("c.p031.test."), but with a forged NSEC3
    record prepended to its AUTHORITY section; that forged record is signed
    using a sibling zone's ("attacker.p031.test.") signing key.  The sibling
    zone's NSEC3 salt is chosen specifically so that the NSEC3 hash for
    "grandsib.c.p031.test." salted with the sibling zone's salt sorts before
    the NSEC3 hash for the same name salted with the child zone's salt.  A
    vulnerable resolver treats such a response as sufficient to prove that the
    grandchild zone is an insecure one.
    """

    matcher = Qname("grandsib.c.p031.test.") & Qtype(dns.rdatatype.DS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        assert qctx.zone
        assert qctx.zone.origin
        parent_origin = qctx.zone.origin.parent()
        sibling_origin = dns.name.from_text("attacker", origin=parent_origin)

        nsec3param = qctx.zones[sibling_origin].get_rdataset(
            sibling_origin, dns.rdatatype.NSEC3PARAM
        )
        assert nsec3param

        # Salt for this zone is specifically chosen at signing time; see
        # docstring above and bootstrap() in tests_nsec_grandparent.py.
        forged_nsec3_hash = dns.dnssec.nsec3_hash(
            qctx.qname, nsec3param[0].salt, nsec3param[0].iterations, 1
        )
        forged_nsec3_owner = dns.name.from_text(
            forged_nsec3_hash, origin=sibling_origin
        )
        forged_nsec3_rrset = nsec3(
            forged_nsec3_owner,
            forged_nsec3_hash,
            salt=nsec3param[0].salt,
            iterations=nsec3param[0].iterations,
        )

        sibling_key = qctx.keys[sibling_origin][0]
        forged_nsec3_rrsig = qctx.sign(forged_nsec3_rrset, key=sibling_key)

        qctx.response.authority.insert(0, forged_nsec3_rrset)
        qctx.response.authority.insert(1, forged_nsec3_rrsig)

        yield DnsResponseSend(qctx.response)


class DummyRrsigGrandchildDsNsecHandler(GrandchildDsNsecHandler, abc.ABC):
    """
    Adds one extra RRSIG to the AUTHORITY section: a dummy one that uses the
    NSEC record's owner name as the signer name and an unknown signing
    algorithm (0).  Subclasses add this extra record either before or after the
    RRSIG prepared using the grandparent's signing key.  This is done to verify
    whether the resolver under test correctly determines the NSEC signer's
    authority boundary.
    """

    dummy_first: bool

    def rrsigs(self, genuine: dns.rdata.Rdata) -> list[dns.rdata.Rdata]:
        dummy = genuine.replace(algorithm=0, signer=self.qname)
        return [dummy, genuine] if self.dummy_first else [genuine, dummy]


class DummyRrsigFirstGrandchildDsNsecHandler(DummyRrsigGrandchildDsNsecHandler):
    qname = "grand-dummy-first.c.p031.test."
    dummy_first = True


class DummyRrsigLastGrandchildDsNsecHandler(DummyRrsigGrandchildDsNsecHandler):
    qname = "grand-dummy-last.c.p031.test."
    dummy_first = False


class ManyRrsigsGrandchildDsNsecHandler(GrandchildDsNsecHandler, abc.ABC):
    """
    Adds multiple extra RRSIG to the AUTHORITY section, each of which uses a
    different key tag and a bogus one-byte signature.  Subclasses only define
    the total number of RRSIG records to put in the AUTHORITY section
    (including the one prepared using the grandparent's signing key).  This is
    done to verify whether the resolver under test correctly enforces a count
    cap on NSEC insecurity proofs.
    """

    total_rrsigs: int

    def rrsigs(self, genuine: dns.rdata.Rdata) -> list[dns.rdata.Rdata]:
        dummies = [
            genuine.replace(algorithm=0, key_tag=key_tag, signature=b"\0")
            for key_tag in range(self.total_rrsigs - 1)
        ]
        return dummies + [genuine]


class TooManyRrsigsGrandchildDsNsecHandler(ManyRrsigsGrandchildDsNsecHandler):
    qname = "grand-too-many.c.p031.test."
    total_rrsigs = MAX_VALIDATIONS_PER_FETCH


class AlmostTooManyRrsigsGrandchildDsNsecHandler(ManyRrsigsGrandchildDsNsecHandler):
    qname = "grand-almost-too-many.c.p031.test."
    total_rrsigs = MAX_VALIDATIONS_PER_FETCH - 1


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR, default_aa=True)
    server.install_response_handlers(
        ChildNsHandler(),
        GrandchildAHandler(),
        GrandchildDsNsecHandler(),
        GrandchildDsNsec3Handler(),
        GrandsiblingDsHandler(),
        DummyRrsigFirstGrandchildDsNsecHandler(),
        DummyRrsigLastGrandchildDsNsecHandler(),
        TooManyRrsigsGrandchildDsNsecHandler(),
        AlmostTooManyRrsigsGrandchildDsNsecHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
