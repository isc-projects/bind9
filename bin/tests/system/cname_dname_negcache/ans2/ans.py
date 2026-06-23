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

from dns import name, rcode, rdataclass, rdatatype, rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QnameQtypeHandler,
    QueryContext,
    StaticResponseHandler,
)


def build_rrset(
    qname: name.Name | str,
    rtype: rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> rrset.RRset:
    return rrset.from_text(qname, ttl, rdataclass.IN, rtype, rdata)


class FooTestNsHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["foo.test."]
    qtypes = [rdatatype.NS]
    answer = [build_rrset("foo.test.", rdatatype.NS, "ns.foo.test.")]
    additional = [build_rrset("ns.foo.test.", rdatatype.A, "10.53.0.2")]


class DelayedDnameNegHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["foo.test."]
    qtypes = [rdatatype.DNAME]
    authority = [
        build_rrset(
            "foo.test.",
            rdatatype.SOA,
            "ns.test. op.ns.test. 2081509183 86400 3600 3600000 300",
        )
    ]
    delay = 1


class DnamePosHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["a.foo.test."]
    qtypes = [rdatatype.A]
    answer = [
        build_rrset("foo.test.", rdatatype.DNAME, "bar.test."),
        build_rrset("a.foo.test.", rdatatype.CNAME, "a.bar.test."),
    ]


class CnameHandler(QnameQtypeHandler):
    qnames = ["cname.foo.test."]
    qtypes = [rdatatype.CNAME, rdatatype.A]
    answer = [build_rrset("cname.foo.test.", rdatatype.CNAME, "cname.foo.test.")]
    authority = [
        build_rrset(
            "cname.foo.test.",
            rdatatype.SOA,
            "ns.test. op.ns.test. 2081509183 86400 3600 3600000 300",
        )
    ]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        if qctx.qtype == rdatatype.CNAME:
            qctx.response.authority.extend(self.authority)
            yield DnsResponseSend(qctx.response, authoritative=True, delay=1)
        else:
            qctx.response.answer.extend(self.answer)
            yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=rcode.NOERROR)
    server.install_response_handlers(
        FooTestNsHandler(), DelayedDnameNegHandler(), DnamePosHandler(), CnameHandler()
    )
    server.run()


if __name__ == "__main__":
    main()
