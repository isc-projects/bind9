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
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    ControllableAsyncDnsServer,
    QueryContext,
    ResponseHandler,
)
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Domain, LabelPredicate, Matcher, Qtype


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class DelayLabel(LabelPredicate):
    """
    Match queries whose leftmost label is the delay in milliseconds.
    """

    def __init__(self) -> None:
        super().__init__(0, bytes.isdigit, "the delay in milliseconds")


class AHandler(ResponseHandler):
    matcher: Matcher = Qtype(dns.rdatatype.A)

    def delay(self, qctx: QueryContext) -> float:
        return 0.0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        a_rrset = rrset(qctx.qname, dns.rdatatype.A, "192.0.2.1")
        qctx.response.answer.append(a_rrset)
        yield DnsResponseSend(qctx.response, delay=self.delay(qctx))


class AaaaHandler(ResponseHandler):
    matcher: Matcher = Qtype(dns.rdatatype.AAAA)

    def delay(self, qctx: QueryContext) -> float:
        return 0.0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        aaaa_rrset = rrset(qctx.qname, dns.rdatatype.AAAA, "2001:db8:beef::1")
        qctx.response.answer.append(aaaa_rrset)
        yield DnsResponseSend(qctx.response, delay=self.delay(qctx))


class DelayedAHandler(AHandler):
    matcher = Domain("latency.example2.") & DelayLabel() & Qtype(dns.rdatatype.A)

    def delay(self, qctx: QueryContext) -> float:
        return int(qctx.qname.labels[0]) / 1000


class DelayedAaaaHandler(AaaaHandler):
    matcher = Domain("latency.example2.") & DelayLabel() & Qtype(dns.rdatatype.AAAA)

    def delay(self, qctx: QueryContext) -> float:
        return int(qctx.qname.labels[0]) / 1000


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    server.install_response_handlers(
        DelayedAHandler(), DelayedAaaaHandler(), AHandler(), AaaaHandler()
    )
    server.run()


if __name__ == "__main__":
    main()
