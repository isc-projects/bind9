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

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qname, Qtype

from ..dnssec_nsec3_ans import minimal_covering_nsec3


class AncestorWildcardNsec3Handler(ResponseHandler):
    """
    This handler imitates successfully spoofing a response to a
    "b.victim2.evil.f025.test/A" query sent to a server authoritative for the
    "evil.f025.test." domain.  The spoofed response contains the wildcard A
    record from the "evil.f025.test." zone and a forged NSEC3 record proving
    that the QNAME's parent (and thus also the QNAME itself) does not exist and
    therefore the wildcard match is valid.  However, the forged NSEC3 record is
    signed using the DNSKEY belonging to the parent zone ("f025.test.").  A
    vulnerable resolver validates such a response as secure, enabling names in
    the child zone to be redirected to that zone's wildcard target using the
    parent zone's signing key.
    """

    matcher = Qname("b.victim2.evil.f025.test.") & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        assert qctx.zone
        assert qctx.zone.origin
        parent_origin = qctx.zone.origin.parent()
        parent_signing_key = qctx.keys[parent_origin][0]

        forged_nsec3_covering_rrset = minimal_covering_nsec3(
            qctx.qname.parent(), parent_origin
        )
        forged_nsec3_covering_rrsig = qctx.sign(
            forged_nsec3_covering_rrset, key=parent_signing_key
        )

        qctx.response.authority = [
            forged_nsec3_covering_rrset,
            forged_nsec3_covering_rrsig,
        ]

        yield DnsResponseSend(qctx.response)


def main() -> None:
    keys = common.load_keys()
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handlers(
        AncestorWildcardNsec3Handler(),
        f055.F055Handler(keys),
    )
    server.run()


if __name__ == "__main__":
    main()
