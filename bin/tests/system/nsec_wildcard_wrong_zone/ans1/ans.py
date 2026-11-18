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

import dns.name
import dns.rcode
import dns.rdatatype

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.dnssec import NonExistenceProver
from isctest.asyncserver.matchers import Qname, Qtype


class AttackNxdomainHandler(ResponseHandler):
    """
    Respond to foo.victim.example/A, which the victim's wildcard matches, with
    a forged NXDOMAIN: the victim's NSEC covering the name (already in the
    prepared wildcard answer), the victim's SOA, and, as the proof that the
    wildcard *.victim.example does not exist, an NSEC covering it from the
    attacker's sibling zone, abc.example.

    A validator that only compares the names takes the second NSEC as the
    proof that no wildcard matches and marks the NXDOMAIN secure.
    """

    matcher = Qname("foo.victim.example.") & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.NXDOMAIN)
        qctx.response.answer.clear()

        assert qctx.soa
        soa_rrsig = qctx.get_rrsig(qctx.soa)
        assert soa_rrsig
        qctx.response.authority.extend([qctx.soa, soa_rrsig])

        NonExistenceProver.for_query(
            zone=qctx.zones[dns.name.from_text("abc.example.")],
            qname=dns.name.from_text("*.victim.example."),
            qclass=qctx.qclass,
            response=qctx.response,
        ).prove_ent()

        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(AttackNxdomainHandler())
    server.run()


if __name__ == "__main__":
    main()
