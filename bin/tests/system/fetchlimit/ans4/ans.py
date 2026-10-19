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
from isctest.asyncserver.commands import ToggleResponsesCommand


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class MaybeDelayedAddressAnswerHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            addr = "192.0.2.1" if qctx.qtype == dns.rdatatype.A else "2001:db8:beef::1"
            answer_rrset = rrset(qctx.qname, qctx.qtype, addr)
            qctx.response.answer.append(answer_rrset)

        delay = 0.05 if qctx.qname.labels[0].startswith(b"latency") else 0.00
        yield DnsResponseSend(qctx.response, delay=delay)


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    server.install_control_command(ToggleResponsesCommand())
    server.install_response_handlers(MaybeDelayedAddressAnswerHandler())
    server.run()


if __name__ == "__main__":
    main()
