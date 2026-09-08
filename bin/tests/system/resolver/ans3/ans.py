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
    rrset_from_list,
    soa_rrset,
)


class ApexNSHandler(StaticResponseHandler):
    matcher = Qname("example.net.") & Qtype(dns.rdatatype.NS)
    answer = [
        rrset(
            matcher.of(Qname).qnames[0],
            dns.rdatatype.NS,
            f"ns.{matcher.of(Qname).qnames[0]}",
        )
    ]
    additional = [
        rrset(f"ns.{matcher.of(Qname).qnames[0]}", dns.rdatatype.A, "10.53.0.3")
    ]


class AttackDnameHandler(StaticResponseHandler):
    matcher = Qname("www.example.attack.example.net", "isc.attack.example.net.")
    answer = [rrset("attack.example.net.", dns.rdatatype.DNAME, "org.")]


class BadCnameHandler(StaticResponseHandler):
    matcher = Qname("badcname.example.net.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.CNAME, "badcname.example.org.")]


class BadGoodDnameNsHandler(StaticResponseHandler):
    matcher = Qname("baddname.example.net.", "gooddname.example.net.") & Qtype(
        dns.rdatatype.NS
    )
    authority = [soa_rrset("example.net.")]


class CnameSubHandler(StaticResponseHandler):
    matcher = Qname("cname.sub.example.org.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.CNAME, "ok.sub.example.org.")]


class ExampleOrgHandler(StaticResponseHandler):
    matcher = Qname("example.org.") & Qtype(dns.rdatatype.A)
    answer = [
        rrset(matcher.of(Qname).qnames[0], matcher.of(Qtype).qtypes[0], "1.2.3.4")
    ]


class FooBadDnameHandler(StaticResponseHandler):
    matcher = Qname("foo.baddname.example.net.")
    answer = [
        rrset("baddname.example.net.", dns.rdatatype.DNAME, "baddname.example.org.")
    ]


class FooBarSubTld1Handler(StaticResponseHandler):
    matcher = Qname("foo.bar.sub.tld1.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.TXT, "baz")]


class FooGlueInAnswerHandler(StaticResponseHandler):
    matcher = Qname("foo.glue-in-answer.example.org.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.A, "192.0.2.1")]


class FooGoodDnameHandler(StaticResponseHandler):
    matcher = Qname("foo.gooddname.example.net.")
    answer = [
        rrset("gooddname.example.net.", dns.rdatatype.DNAME, "gooddname.example.org.")
    ]


class GoodCnameHandler(StaticResponseHandler):
    matcher = Qname("goodcname.example.net.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.CNAME, "goodcname.example.org.")]


class IscHandler(StaticResponseHandler):
    matcher = Qname("isc.org.") & Qtype(dns.rdatatype.A)
    answer = [
        rrset(matcher.of(Qname).qnames[0], matcher.of(Qtype).qtypes[0], "1.2.3.4")
    ]


class LameExampleOrgDelegation(DelegationHandler):
    domains = ["lame.example.org."]
    server_number = 3


class LargeReferralHandler(StaticResponseHandler):
    matcher = Qname("large-referral.example.net.") & Qtype(dns.rdatatype.NS)
    authority = [
        rrset_from_list(
            matcher.of(Qname).qnames[0],
            dns.rdatatype.NS,
            [f"ns{i}.fake.redirect.com." for i in range(1, 1000)],
        )
    ]


class LongCnameHandler(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname.labels[0].startswith(b"longcname")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        first_label = qctx.qname.labels[0].replace(b"longcname", b"longcnamex")
        cname_target = f"{dns.name.Name((first_label,) + qctx.qname.labels[1:])}"
        qctx.response.answer.append(
            rrset(qctx.qname, dns.rdatatype.CNAME, cname_target)
        )
        yield DnsResponseSend(qctx.response)


class NodataHandler(StaticResponseHandler):
    matcher = Qname("nodata.example.net.")


class NoresponseHandler(IgnoreAllQueries):
    matcher = Qname("noresponse.example.net.")


class NsHandler(StaticResponseHandler):
    matcher = Qname("ns.example.net.")
    answer = [rrset(matcher.qnames[0], dns.rdatatype.A, "10.53.0.3")]


class NxdomainHandler(StaticResponseHandler):
    matcher = Qname("nxdomain.example.net.")
    rcode = dns.rcode.NXDOMAIN


class OkSubHandler(ResponseHandler):
    matcher = Qname("ok.sub.example.org.", "www.ok.sub.example.org.")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(rrset(qctx.qname, dns.rdatatype.A, "192.0.2.1"))
        yield DnsResponseSend(qctx.response)


class PartialFormerrHandler(DomainHandler):
    domains = ["partial-formerr."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(
            rrset(qctx.qname, dns.rdatatype.A, "10.53.0.3", ttl=1)
        )
        yield DnsResponseSend(qctx.response)


class WwwDnameSubHandler(StaticResponseHandler):
    matcher = Qname("www.dname.sub.example.org.")
    answer = [
        rrset("dname.sub.example.org.", dns.rdatatype.DNAME, "ok.sub.example.org.")
    ]


class WwwGoodDnameHandler(StaticResponseHandler):
    matcher = Qname("www.example.gooddname.example.net")
    answer = [rrset("gooddname.example.net.", dns.rdatatype.DNAME, "org.")]


class WwwHandler(ResponseHandler):
    matcher = Qname("www.example.net.")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            qctx.response.answer.append(rrset(qctx.qname, dns.rdatatype.A, "192.0.2.1"))
        elif qctx.qtype == dns.rdatatype.AAAA:
            qctx.response.answer.append(
                rrset(qctx.qname, dns.rdatatype.AAAA, "2001:db8:beef::1")
            )
        yield DnsResponseSend(qctx.response)


class FallbackHandler(StaticResponseHandler):
    answer = [rrset("www.example.com.", dns.rdatatype.A, "1.2.3.4")]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ApexNSHandler(),
        AttackDnameHandler(),
        BadCnameHandler(),
        BadGoodDnameNsHandler(),
        CnameSubHandler(),
        ExampleOrgHandler(),
        FooBadDnameHandler(),
        FooBarSubTld1Handler(),
        FooGoodDnameHandler(),
        FooGlueInAnswerHandler(),
        Gl6412AHandler(),
        Gl6412Handler(),
        Gl6412Ns2Handler(),
        Gl6412Ns3Handler(),
        GoodCnameHandler(),
        IscHandler(),
        LameExampleOrgDelegation(),
        LargeReferralHandler(),
        LongCnameHandler(),
        NodataHandler(),
        NoresponseHandler(),
        NsHandler(),
        NxdomainHandler(),
        OkSubHandler(),
        PartialFormerrHandler(),
        WwwDnameSubHandler(),
        WwwGoodDnameHandler(),
        WwwHandler(),
    )

    server.install_response_handler(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
