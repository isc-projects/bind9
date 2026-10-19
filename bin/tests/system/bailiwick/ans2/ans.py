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

from isctest.asyncserver import QueryContext
from isctest.asyncserver.actions import DnsResponseSend
from isctest.template import ANS3

from ..bailiwick_ans import ResponseSpoofer, a, cname, dname, ns, spoofing_server, txt

ATTACKER_IP = ANS3.ip


class UnsolicitedNsSpoofer(ResponseSpoofer, mode="unsolicited-ns"):

    qname = "trigger.victim."

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)

        response.answer.append(txt(qctx.qname, "spoofed answer with extra NS"))
        response.authority.append(ns("victim.", "ns.attacker."))

        yield DnsResponseSend(response, authoritative=True)


class ParentGlueSpoofer(ResponseSpoofer, mode="parent-glue"):

    qname = "trigger.victim."

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)

        response.authority.append(ns("trigger.victim.", "ns.victim."))
        response.additional.append(a("ns.victim.", ATTACKER_IP))

        yield DnsResponseSend(response, authoritative=False)


class DnameSpoofer(ResponseSpoofer, mode="dname"):

    qname = "trigger.victim."

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.prepare_new_response(with_zone_data=False)

        response.answer.append(cname(qctx.qname, "trigger.attacker."))
        response.answer.append(dname("victim.", "attacker."))

        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    spoofing_server().run()


if __name__ == "__main__":
    main()
