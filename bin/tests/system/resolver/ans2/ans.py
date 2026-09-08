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
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.handlers import (
    DomainHandler,
    IgnoreAllQueries,
    StaticResponseHandler,
)
from isctest.asyncserver.matchers import Qname, Qtype

from ..resolver_ans import (
    DelegationHandler,
    Gl6412AHandler,
    Gl6412Handler,
    Gl6412Ns2Handler,
    Gl6412Ns3Handler,
    rrset,
    setup_delegation,
)


class BadGoodDnameNsHandler(StaticResponseHandler):
    matcher = Qname("baddname.example.org.", "gooddname.example.org.") & Qtype(
        dns.rdatatype.NS
    )
    answer = [rrset("example.org.", dns.rdatatype.NS, "a.root-servers.nil.")]
    authoritative = True


def _cname_rrsets(
    qname: dns.name.Name | str,
) -> tuple[dns.rrset.RRset, dns.rrset.RRset]:
    return (
        rrset(qname, dns.rdatatype.CNAME, f"{qname}"),
        rrset(qname, dns.rdatatype.A, "1.2.3.4"),
    )


class Cname1Handler(StaticResponseHandler):
    matcher = Qname("cname1.example.com.")
    # Data for the "cname + other data / 1" test
    answer = _cname_rrsets(matcher.qnames[0])
    authoritative = False


class Cname2Handler(StaticResponseHandler):
    matcher = Qname("cname2.example.com.")
    # Data for the "cname + other data / 2" test: same RRs in opposite order
    answer = tuple(reversed(_cname_rrsets(matcher.qnames[0])))
    authoritative = False


class ExampleOrgHandler(ResponseHandler):
    matcher = Qname(
        "www.example.org",
        "badcname.example.org",
        "goodcname.example.org",
        "foo.baddname.example.org",
        "foo.gooddname.example.org",
    )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Data for address/alias filtering.
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, "192.0.2.1")
            qctx.response.answer.append(a_rrset)
        elif qctx.qtype == dns.rdatatype.AAAA:
            aaaa_rrset = rrset(qctx.qname, dns.rdatatype.AAAA, "2001:db8:beef::1")
            qctx.response.answer.append(aaaa_rrset)
        yield DnsResponseSend(qctx.response, authoritative=True)


class NoResponseExampleUdpHandler(IgnoreAllQueries):
    matcher = Qname("noresponse.exampleudp.net.")


class RootNsHandler(ResponseHandler):
    matcher = Qname("example.com.", "com.", "example.org.", "org.", "net.") & Qtype(
        dns.rdatatype.NS
    )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        root_ns = rrset(qctx.qname, dns.rdatatype.NS, "a.root-servers.nil.")
        qctx.response.answer.append(root_ns)
        yield DnsResponseSend(qctx.response, authoritative=True)


class Ns2Delegation(DelegationHandler):
    domains = ["exampleudp.net."]
    server_number = 2


class Ns3Delegation(DelegationHandler):
    domains = [
        "example.net.",
        "isc.org.",
        "lame.example.org.",
        "sub.example.org.",
    ]
    server_number = 3


class Ns3GlueInAnswerDelegation(DelegationHandler):
    domains = ["glue-in-answer.example.org."]
    server_number = 3

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        async for dns_response in super().get_responses(qctx):
            dns_response.response.answer += dns_response.response.additional
            yield dns_response


class Ns4Delegation(DelegationHandler):
    domains = ["broken."]
    server_number = 4


class Ns6Delegation(DelegationHandler):
    domains = [
        "redirect.com.",
        "tld1.",
    ]
    server_number = 6


class Ns7Delegation(DelegationHandler):
    domains = ["tld2."]
    server_number = 7


class PartialFormerrHandler(DomainHandler, StaticResponseHandler):
    domains = ["partial-formerr."]
    authoritative = False
    rcode = dns.rcode.FORMERR


class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        setup_delegation(qctx, "below.www.example.com.", 3)
        yield DnsResponseSend(qctx.response, authoritative=False)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)

    # Install QnameHandlers first
    server.install_response_handlers(
        BadGoodDnameNsHandler(),
        Cname1Handler(),
        Cname2Handler(),
        ExampleOrgHandler(),
        Gl6412AHandler(),
        Gl6412Handler(),
        Gl6412Ns2Handler(),
        Gl6412Ns3Handler(),
        NoResponseExampleUdpHandler(),
        RootNsHandler(),
    )

    # Then install DomainHandlers
    server.install_response_handlers(
        Ns2Delegation(),
        Ns3Delegation(),
        Ns3GlueInAnswerDelegation(),
        Ns4Delegation(),
        Ns6Delegation(),
        Ns7Delegation(),
        PartialFormerrHandler(),
    )

    # Finally, install the fallback handler
    server.install_response_handler(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
