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

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Domain, Qtype


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def nsec(owner: str | dns.name.Name, next_name: str, types: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NSEC, f"{next_name} {types}")


class AddGarbageSignedNsecRecordsHandler(ResponseHandler):
    """
    This handler imitates successfully spoofing a response to a resolver query
    for any name in the (unsigned) "child.p22.hack" domain to a server
    authoritative for the "p22.hack" domain.  The spoofed response contains a
    valid insecure delegation (prepared using zone data) with extra NSEC
    records appended to the AUTHORITY section; these records have bogus DNSSEC
    signatures, but a vulnerable resolver treats them as sufficient for
    negative response synthesis for covered names in the "p22.hack" domain.

    QTYPE=DS queries are exempt from this special handling and are responded to
    using zone data.
    """

    matcher = Domain("child.p22.hack.") & ~Qtype(dns.rdatatype.DS)

    def add_garbage_signed_nsec(
        self, qctx: QueryContext, *, owner: str, next_name: str
    ) -> None:
        assert qctx.zone

        nsec_rrset = nsec(
            f"{owner}.{qctx.zone.origin}",
            f"{next_name}.{qctx.zone.origin}",
            "A RRSIG NSEC",
        )
        nsec_rrsig = qctx.sign(nsec_rrset, bogus=True)

        qctx.response.authority.append(nsec_rrset)
        qctx.response.authority.append(nsec_rrsig)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # NODATA for "victim.p22.hack.", as an empty non-terminal
        self.add_garbage_signed_nsec(qctx, owner="t", next_name="sub.victim")

        # NXDOMAIN for "aac.p22.hack."
        self.add_garbage_signed_nsec(qctx, owner="aab", next_name="az")

        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(AddGarbageSignedNsecRecordsHandler())
    server.run()


if __name__ == "__main__":
    main()
