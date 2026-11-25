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

import asyncio

import dns.flags
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    ControlCommand,
    ControllableAsyncDnsServer,
    QueryContext,
    ResponseHandler,
)
from isctest.asyncserver.handlers import ResponseHandlerWrapper, SingleResponseHandler
from isctest.asyncserver.matchers import Flags, Qname, Qtype

NAME = "nodata.example."


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    *rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, *rdata)


class HeldAddressHandler(SingleResponseHandler):
    """
    Answer a CD=1 A query for nodata.example with unsigned addresses, but
    only once the "release._control." command has been received.  CD=0
    queries are not matched and get the zone's signed NODATA response.

    The RRset has as many records as the negative cache entry built from
    that NODATA response (SOA, NSEC and their RRSIGs), so that a cache
    comparing the two does not stop at the record count.
    """

    matcher = Qname(NAME) & Qtype(dns.rdatatype.A) & Flags(dns.flags.CD)
    rcode = dns.rcode.NOERROR
    answer = [
        rrset(NAME, dns.rdatatype.A, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")
    ]
    authoritative = True


class UntilReleased(ResponseHandlerWrapper):
    """
    Hold the responses of the wrapped handler until the "release._control."
    command has been received.
    """

    def __init__(self, inner: ResponseHandler, release: asyncio.Event) -> None:
        super().__init__(inner)
        self._release = release

    async def _on_query_received(self, qctx: QueryContext) -> None:
        await self._release.wait()


class ReleaseCommand(ControlCommand):
    """
    Release the answers held by HeldAddressHandler.
    """

    control_subdomain = "release"

    def __init__(self, release: asyncio.Event) -> None:
        self._release = release

    def handle(
        self, args: list[str], server: ControllableAsyncDnsServer, qctx: QueryContext
    ) -> str | None:
        self._release.set()
        return "released"


def main() -> None:
    server = ControllableAsyncDnsServer()
    release = asyncio.Event()
    server.install_response_handlers(UntilReleased(HeldAddressHandler(), release))
    server.install_control_command(ReleaseCommand(release))
    server.run()


if __name__ == "__main__":
    main()
