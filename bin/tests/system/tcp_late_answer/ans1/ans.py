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

"""
A forwarder that answers over TCP only and is slow for two names.

Every UDP query is answered with TC=1, so the resolver retries it over
TCP and pipelines the retries of all its fetches on the one TCP
connection it keeps to this server.  Queries on a TCP connection are
read and answered one at a time, so a delayed answer also holds back
the answers to the queries queued behind it on the same connection.
"""

from collections.abc import AsyncGenerator

import dns.flags

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsProtocol,
    QueryContext,
    ResponseHandler,
)
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Once, Protocol, Qname


class TruncateUdpHandler(ResponseHandler):
    """
    Answer every UDP query with TC=1 so the resolver retries over TCP.
    """

    matcher = Protocol(DnsProtocol.UDP)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.flags |= dns.flags.TC
        yield DnsResponseSend(qctx.response)


class DelayedAnswerHandler(ResponseHandler):
    """
    Answer from zone data after the delay set by the subclass.
    """

    delay = 0.0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        yield DnsResponseSend(qctx.response, delay=self.delay)


class LateAnswerHandler(DelayedAnswerHandler):
    """
    Answer after the resolver's per-query TCP timeout (1.2 s) has passed
    for the query sent right behind this one.  Only the first query is
    delayed: should the resolver time it out and resend it, the resend
    must not hold up the queries behind it again.
    """

    matcher = Once(Qname("late.test."))
    delay = 1.8


class CanceledAnswerHandler(DelayedAnswerHandler):
    """
    Answer after the resolver has had time to cancel the fetch, but
    before its per-query timeout.
    """

    matcher = Qname("canceled.test.")
    delay = 0.5


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(TruncateUdpHandler())
    server.install_response_handlers(
        LateAnswerHandler(),
        CanceledAnswerHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
