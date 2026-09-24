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

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import CloseConnection, DnsResponseSend, ResponseDrop
from isctest.asyncserver.handlers import IgnoreAllQueries
from isctest.asyncserver.matchers import Domain


class SilentHandler(IgnoreAllQueries):
    """
    Handler that doesn't respond.
    """

    matcher = Domain("silent.example")


class CloseHandler(ResponseHandler):
    """
    Handler that doesn't respond and closes TCP connection.
    """

    matcher = Domain("close.example")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[CloseConnection, None]:
        yield CloseConnection()


class SilentThenServfailHandler(ResponseHandler):
    """
    Handler that drops one query and response to the next one with SERVFAIL.
    """

    matcher = Domain("silent-then-servfail.example")
    counter = 0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend | ResponseDrop, None]:
        if self.counter % 2 == 0:
            yield ResponseDrop()
        else:
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            yield DnsResponseSend(qctx.response, authoritative=False)
        self.counter += 1


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(
        CloseHandler(),
        SilentHandler(),
        SilentThenServfailHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
