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
from isctest.asyncserver.actions import CloseConnection
from isctest.asyncserver.handlers import IgnoreAllQueries
from isctest.asyncserver.matchers import Domain, Matcher


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


class EverySecond(Matcher):
    """
    Match every second query the given matcher matches, the first one
    included.
    """

    def __init__(self, matcher: Matcher) -> None:
        self._matcher = matcher
        self._count = 0

    def match(self, qctx: QueryContext) -> bool:
        if not self._matcher.match(qctx):
            return False
        self._count += 1
        return self._count % 2 == 1

    def __str__(self) -> str:
        return f"every second query where {self._matcher}"


class SilentEverySecondQueryHandler(IgnoreAllQueries):
    """
    Handler that doesn't respond to every second query, so that the next
    one gets the server's SERVFAIL.
    """

    matcher = EverySecond(Domain("silent-then-servfail.example"))


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.SERVFAIL)
    server.install_response_handlers(
        CloseHandler(),
        SilentHandler(),
        SilentEverySecondQueryHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
