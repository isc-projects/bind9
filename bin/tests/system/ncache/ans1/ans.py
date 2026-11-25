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
import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import ControlCommand, ControllableAsyncDnsServer, QueryContext
from isctest.asyncserver.handlers import ResponseHandlerWrapper, StaticResponseHandler
from isctest.asyncserver.matchers import Matcher, Qname, Qtype

NAME = "nodata.example."

RELEASE = asyncio.Event()


class CdFlag(Matcher):
    """
    Match queries with the CD flag set.
    """

    def match(self, qctx: QueryContext) -> bool:
        return bool(qctx.query.flags & dns.flags.CD)


class HeldAddressHandler(StaticResponseHandler):
    """
    Answer a CD=1 A query for nodata.example with unsigned addresses, but
    only once the "release._control." command has been received.  CD=0
    queries are not matched and get the zone's signed NODATA response.

    The RRset has as many records as the negative cache entry built from
    that NODATA response (SOA, NSEC and their RRSIGs), so that a cache
    comparing the two does not stop at the record count.
    """

    matcher = Qname(NAME) & Qtype(dns.rdatatype.A) & CdFlag()
    rcode = dns.rcode.NOERROR
    answer = [
        dns.rrset.from_text(
            NAME, 300, "IN", "A", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"
        )
    ]
    authoritative = True


class UntilReleased(ResponseHandlerWrapper):
    """
    Hold the responses of the wrapped handler until the "release._control."
    command has been received.
    """

    async def _on_query_received(self, qctx: QueryContext) -> None:
        await RELEASE.wait()


class ReleaseCommand(ControlCommand):
    """
    Release the answers held by HeldAddressHandler.
    """

    control_subdomain = "release"

    def handle(
        self, args: list[str], server: ControllableAsyncDnsServer, qctx: QueryContext
    ) -> str | None:
        RELEASE.set()
        return "released"


def main() -> None:
    server = ControllableAsyncDnsServer()
    server.install_response_handler(UntilReleased(HeldAddressHandler()))
    server.install_control_command(ReleaseCommand())
    server.run()


if __name__ == "__main__":
    main()
