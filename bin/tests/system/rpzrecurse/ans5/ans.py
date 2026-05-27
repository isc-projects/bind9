"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator

import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)


class ReplyA(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        a_rrset = dns.rrset.from_text(
            qctx.qname, 300, qctx.qclass, dns.rdatatype.A, "10.53.0.5"
        )
        qctx.response.answer.append(a_rrset)
        yield DnsResponseSend(qctx.response)


class DelayNs(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        ns_rrset = dns.rrset.from_text(
            "foo.child.example.tld.",
            300,
            qctx.qclass,
            dns.rdatatype.NS,
            "ns5.foo.",
        )
        qctx.response.answer.append(ns_rrset)
        yield DnsResponseSend(qctx.response, delay=3)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(ReplyA(), DelayNs())
    server.run()


if __name__ == "__main__":
    main()
