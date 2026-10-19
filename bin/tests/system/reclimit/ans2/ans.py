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

from isctest.asyncserver import ControllableAsyncDnsServer, QueryContext
from isctest.asyncserver.actions import DnsResponseSend

from ..reclimit_ans import (
    CountAndResetHandler,
    DirectExampleHandler,
    FallbackNxdomainHandler,
    IndirectExampleOrgHandler,
    LimitControlCommand,
    Ns1Example,
    Ns1ExampleOrgHandler,
    ReclimitHandler,
    ReclimitState,
    a,
    ns,
)


class Ns1ExampleNetHandler(ReclimitHandler):
    matcher = Ns1Example("net")

    async def _get_counted_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        current_ns_number = int(qctx.qname.labels[1])
        next_ns_block_start = (current_ns_number + 1) * 16
        for offset in range(1, 16):
            target_ns_number = next_ns_block_start + offset
            qctx.response.authority.append(
                ns(
                    f"{current_ns_number}.example.net.",
                    f"ns1.{target_ns_number}.example.net.",
                )
            )
            qctx.response.additional.append(
                a(f"ns1.{target_ns_number}.example.net.", 7)
            )

        yield DnsResponseSend(qctx.response, authoritative=False)


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    state = ReclimitState(indirect_send_response_default=False)
    server.install_response_handlers(
        CountAndResetHandler(state),
        DirectExampleHandler(state, 2),
        IndirectExampleOrgHandler(state, 2),
        Ns1ExampleOrgHandler(state),
        Ns1ExampleNetHandler(state),
        FallbackNxdomainHandler(state),
    )
    server.install_control_command(LimitControlCommand(state))
    server.run()


if __name__ == "__main__":
    main()
