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

import dns.flags
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qname

ZONE = "response.test."


def txt(name: dns.name.Name, text: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        name, 300, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{text}"'
    )


class FreshResponseHandler(ResponseHandler):
    """
    Send a response carrying the server's defaults but none of the zone data
    prepared for the query.
    """

    matcher = Qname(f"fresh.{ZONE}")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        yield DnsResponseSend(qctx.prepare_new_response(with_zone_data=False))


class RenderedBeforeSendHandler(ResponseHandler):
    """
    Render the response to wire before changing it, as a handler measuring
    its size would; the changes must still reach the client.
    """

    matcher = Qname(f"rendered.{ZONE}")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.to_wire()
        qctx.response.answer.append(txt(qctx.qname, "added after rendering"))
        yield DnsResponseSend(qctx.response, authoritative=False)


class RollbackHandler(ResponseHandler):
    """
    Spoil the response prepared from zone data, then discard the changes with
    QueryContext.prepare_new_response() before sending it.
    """

    matcher = Qname(f"rollback.{ZONE}")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        qctx.response.flags &= ~dns.flags.AA
        qctx.response.answer.append(txt(qctx.qname, "spoiled"))
        yield DnsResponseSend(qctx.prepare_new_response())


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOTIMP)
    server.install_response_handlers(
        FreshResponseHandler(),
        RenderedBeforeSendHandler(),
        RollbackHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
