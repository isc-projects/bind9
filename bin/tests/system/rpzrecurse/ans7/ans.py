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

import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qname, Qtype


class ReplyA(ResponseHandler):
    matcher = Qname("trigger.cve-2026-97313.test.") & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        a_rrset = dns.rrset.from_text(
            qctx.qname, 300, qctx.qclass, dns.rdatatype.A, "10.53.0.99"
        )
        qctx.response.answer.append(a_rrset)
        yield DnsResponseSend(qctx.response)


class ReplyDefault(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        soa_rrset = dns.rrset.from_text(
            ".",
            1,  # Important: this should be 1 so it expires early
            qctx.qclass,
            dns.rdatatype.SOA,
            "a.root-servers.test. root.test. 1 3600 1200 604800 1",
        )
        qctx.response.authority.append(soa_rrset)
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(ReplyA(), ReplyDefault())
    server.run()


if __name__ == "__main__":
    main()
