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

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qtype
from isctest.template import ANS5

from ..rpzrecurse_ans import a, ns


class AHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(a(qctx.qname, ANS5.ip))
        yield DnsResponseSend(qctx.response)


class DelayedNsHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.NS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(ns("foo.child.example.tld.", "ns5.foo."))
        yield DnsResponseSend(qctx.response, delay=3)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(AHandler(), DelayedNsHandler())
    server.run()


if __name__ == "__main__":
    main()
