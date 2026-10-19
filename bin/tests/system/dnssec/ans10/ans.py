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
from isctest.asyncserver.matchers import Qtype


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class AddRrsigToAHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        rrsig = (
            f"A 13 2 60 {2**32-1} 0 12345 {qctx.qname.to_text()} "
            "gB+eISXAhSPZU2i/II0W9ZUhC2SCIrb94mlNvP5092WAeXxqN/vG43/1nmDly2Qs7y5VCjSMOGn85bnaMoAc7w=="
        )
        rrsig_rrset = rrset(qctx.qname, dns.rdatatype.RRSIG, rrsig, ttl=1)
        qctx.response.answer.append(rrsig_rrset)
        yield DnsResponseSend(qctx.response)


class AddNsecToTxtHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.TXT)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        nsec = f"{qctx.qname.to_text()} A NS SOA RRSIG NSEC"
        nsec_rrset = rrset(qctx.qname, dns.rdatatype.NSEC, nsec, ttl=1)
        qctx.response.authority.append(nsec_rrset)
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(AddNsecToTxtHandler(), AddRrsigToAHandler())
    server.run()


if __name__ == "__main__":
    main()
