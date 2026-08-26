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
    ControllableAsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)


class DelayedAddressAnswerHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            addr = "192.0.2.1" if qctx.qtype == dns.rdatatype.A else "2001:db8:beef::1"
            rrset = dns.rrset.from_text(qctx.qname, 300, qctx.qclass, qctx.qtype, addr)
            qctx.response.answer.append(rrset)

        # <delay-in-ms>.<...>.latency...: any labels between the delay and
        # "latency" are ignored; tests use them to bypass the resolver cache
        delay = 0.0
        if b"latency" in qctx.qname.labels[1:] and qctx.qname.labels[0].isdigit():
            delay = int(qctx.qname.labels[0]) / 1000
        yield DnsResponseSend(qctx.response, delay=delay)


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    server.install_response_handler(DelayedAddressAnswerHandler())
    server.run()


if __name__ == "__main__":
    main()
