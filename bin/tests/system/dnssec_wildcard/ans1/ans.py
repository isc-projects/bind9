"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator

import dns.name
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QnameQtypeHandler,
    QueryContext,
)


def append_forged_a_rrset_to_additional(qctx: QueryContext, owner_name: str) -> None:
    # Append a forged wildcard-synthesized record to the response.  The
    # attacker does NOT control the contents of the A record - they have to
    # match the contents of the actual wildcard record present in the zone or
    # else the wildcard RRSIG (see below) won't validate, foiling the attack.
    wildcard_name = dns.name.from_text("*", origin=qctx.zone.origin)
    wildcard_a_rrset = qctx.zone.get_rrset(wildcard_name, dns.rdatatype.A)
    assert wildcard_a_rrset
    forged_a_rrset = dns.rrset.from_rdata_list(
        owner_name, wildcard_a_rrset.ttl, wildcard_a_rrset
    )
    qctx.response.additional.append(forged_a_rrset)

    # Get the RRSIG for the wildcard record from the zone that matched the
    # query.
    wildcard_rrsig = qctx.zone.get_rrset(
        wildcard_name, dns.rdatatype.RRSIG, covers=dns.rdatatype.A
    )
    assert wildcard_rrsig

    # Append the RRSIG for the wildcard record as the signature for the
    # forged A record, making it look as if the A record was synthesized
    # from the wildcard record.
    forged_a_rrsig = dns.rrset.from_rdata_list(
        owner_name, wildcard_rrsig.ttl, wildcard_rrsig
    )
    qctx.response.additional.append(forged_a_rrsig)

    # No proof-of-nonexistence is provided for the QNAME and yet a vulnerable
    # resolver validates the forged A record as a secure response synthesized
    # from a wildcard record.


class WildcardAdditionalHandler(QnameQtypeHandler):
    qnames = ["svc.f043.test."]
    qtypes = [dns.rdatatype.MX]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        append_forged_a_rrset_to_additional(qctx, "victim.f043.test.")
        yield DnsResponseSend(qctx.response)


class ParentWildcardHandler(QnameQtypeHandler):
    qnames = ["q.f045.test."]
    qtypes = [dns.rdatatype.MX]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        append_forged_a_rrset_to_additional(qctx, "svc.child.f045.test.")
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(
        WildcardAdditionalHandler(),
        ParentWildcardHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
