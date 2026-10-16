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

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Qname, Qtype


class Nsec3ParentImpersonationHandler(ResponseHandler):
    """
    This handler imitates successfully spoofing a response to a
    "victim.tld.test/A" query sent to a server authoritative for the
    "tld.test." domain.  The spoofed response contains a crafted NSEC3
    record whose owner name matches the apex of the attacked zone
    ("tld.test."), but it is signed using a DNSKEY belonging to a
    (properly delegated) child zone whose origin is also the NSEC3 hash
    of the parent zone's apex.  A vulnerable resolver validates such a
    response as secure even though the non-existence proof is signed by
    the child zone's signing key and not the parent zone's signing key.
    """

    matcher = Qname("victim.tld.test.") & Qtype(dns.rdatatype.A)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(dns.rcode.NXDOMAIN)

        assert qctx.soa
        qctx.response.authority.append(qctx.soa)
        if soa_rrsig := qctx.get_rrsig(qctx.soa):
            qctx.response.authority.append(soa_rrsig)

        assert qctx.zone
        assert qctx.zone.origin
        parent_apex_hash = dns.dnssec.nsec3_hash(qctx.zone.origin, None, 0, 1)
        child_origin = dns.name.from_text(parent_apex_hash, origin=qctx.zone.origin)
        child_signing_key = qctx.keys[child_origin][0]

        nsec3_rrset = dns.rrset.from_text(
            child_origin,
            300,
            qctx.qclass,
            dns.rdatatype.NSEC3,
            f"1 0 0 - {parent_apex_hash} NS SOA RRSIG DNSKEY NSEC3PARAM",
        )
        nsec3_rrsig = qctx.sign(nsec3_rrset, key=child_signing_key)
        qctx.response.authority.append(nsec3_rrset)
        qctx.response.authority.append(nsec3_rrsig)

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(Nsec3ParentImpersonationHandler())
    server.run()


if __name__ == "__main__":
    main()
