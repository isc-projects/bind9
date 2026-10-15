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

import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qname, Qtype


class AncestorAdditionalHandler(ResponseHandler):
    matcher = Qname("q.f044.test.") & Qtype(dns.rdatatype.MX)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Append a forged record from the child zone to the response.
        forged_a_rrset = dns.rrset.from_text(
            "svc.child.f044.test.", 300, qctx.qclass, dns.rdatatype.A, "6.6.6.6"
        )
        qctx.response.additional.append(forged_a_rrset)

        # Sign the forged child zone record using the parent zone's key.
        forged_a_rrsig = qctx.sign(forged_a_rrset)
        qctx.response.additional.append(forged_a_rrsig)

        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(AncestorAdditionalHandler())
    server.run()


if __name__ == "__main__":
    main()
