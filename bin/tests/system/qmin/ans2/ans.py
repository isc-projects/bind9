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
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Domain
from isctest.template import ANS3, ANS4

from ..qmin_ans import (
    DelayedResponseHandler,
    EntRcodeChanger,
    QueryLogHandler,
    log_query,
)


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class QueryLogger(QueryLogHandler):
    matcher = Domain("1.0.0.2.ip6.arpa.", "fwd.", "good.", "stale.")


class BadHandler(EntRcodeChanger):
    matcher = Domain("bad.")
    rcode = dns.rcode.NXDOMAIN


class UglyHandler(EntRcodeChanger):
    matcher = Domain("ugly.")
    rcode = dns.rcode.FORMERR


class SlowHandler(DelayedResponseHandler):
    matcher = Domain("slow.")
    delay = 0.2


def send_delegation(
    qctx: QueryContext, zone_cut: dns.name.Name, target_addr: str
) -> DnsResponseSend:
    """
    Delegate `zone_cut` to a single in-bailiwick name server, `ns.<zone_cut>`,
    with a single IPv4 glue record (provided in `target_addr`) included in the
    ADDITIONAL section.
    """
    ns_name = "ns." + zone_cut.to_text()
    ns_rrset = rrset(zone_cut, dns.rdatatype.NS, ns_name, ttl=2)
    a_rrset = rrset(ns_name, dns.rdatatype.A, target_addr, ttl=2)

    response = qctx.prepare_new_response(with_zone_data=False)
    response.set_rcode(dns.rcode.NOERROR)
    response.authority.append(ns_rrset)
    response.additional.append(a_rrset)

    return DnsResponseSend(response, authoritative=False)


class StaleDelegationHandler(ResponseHandler):
    """
    `a.b.stale` is a subdomain of `b.stale` and these two subdomains need to be
    delegated to different name servers.  Therefore, their delegations cannot
    be placed in the zone file because the zone cut at `b.stale` would occlude
    the one at `a.b.stale`, so each cut is delegated by a handler of its own.
    """

    address: str

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        log_query(qctx)
        yield send_delegation(
            qctx, self.matcher.of(Domain).matched_domain, self.address
        )


class ABStaleDelegationHandler(StaleDelegationHandler):
    matcher = Domain("a.b.stale.")
    address = ANS3.ip


class BStaleDelegationHandler(StaleDelegationHandler):
    matcher = Domain("b.stale.")
    address = ANS4.ip


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(ABStaleDelegationHandler())
    server.install_response_handlers(BStaleDelegationHandler())
    server.install_response_handlers(
        BadHandler(),
        QueryLogger(),
        SlowHandler(),
        UglyHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
