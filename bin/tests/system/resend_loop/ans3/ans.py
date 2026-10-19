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

import dns.edns
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.handlers import SingleResponseHandler
from isctest.asyncserver.matchers import Domain, Matcher, Qname, Qtype
from isctest.template import ANS3


def rrset(
    qname: dns.name.Name | str,
    rtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, rtype, rdata)


def a(owner: dns.name.Name | str, address: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, address)


def ns(owner: dns.name.Name | str, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)


class RootNsHandler(SingleResponseHandler):
    matcher = Qname(".") & Qtype(dns.rdatatype.NS)
    answer = [ns(".", "a.root-servers.nil.")]
    additional = [a("a.root-servers.nil.", ANS3.ip)]


class ExampleNsHandler(SingleResponseHandler):
    matcher = Qname("example.") & Qtype(dns.rdatatype.NS)
    answer = [ns(matcher.of(Qname).qname, f"ns.{matcher.of(Qname).qname}")]
    additional = [a(f"ns.{matcher.of(Qname).qname}", ANS3.ip)]


class WithCookie(Matcher):
    """
    Match queries carrying an EDNS COOKIE option; the option of the last
    match is kept in `matched_cookie`.
    """

    def __init__(self) -> None:
        self._matched_cookie: dns.edns.CookieOption | None = None

    @property
    def matched_cookie(self) -> dns.edns.CookieOption:
        assert self._matched_cookie is not None, f"{self} has not matched yet"
        return self._matched_cookie

    def match(self, qctx: QueryContext) -> bool:
        for option in qctx.query.options:
            if isinstance(option, dns.edns.CookieOption):
                self._matched_cookie = option
                return True
        return False

    def __str__(self) -> str:
        return "with a COOKIE option"


class BadCookieHandler(ResponseHandler):
    """
    Answer a query that carries a client cookie with BADCOOKIE and a server
    cookie, to trigger the resend loop logic.
    """

    matcher = Domain("example.") & WithCookie()

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        cookie = self.matcher.of(WithCookie).matched_cookie
        cookie.server = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        qctx.response.use_edns(options=[cookie])
        qctx.response.set_rcode(dns.rcode.BADCOOKIE)
        yield DnsResponseSend(qctx.response)


class ExampleServfailHandler(SingleResponseHandler):
    matcher = Domain("example.")
    rcode = dns.rcode.SERVFAIL


class TestDotComServFailHandler(SingleResponseHandler):
    matcher = Qname("test.com.")
    authoritative = False
    rcode = dns.rcode.SERVFAIL


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        RootNsHandler(),
        ExampleNsHandler(),
        TestDotComServFailHandler(),
    )
    server.install_response_handlers(BadCookieHandler())
    server.install_response_handlers(ExampleServfailHandler())
    server.run()


if __name__ == "__main__":
    main()
