# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
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

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    QnameQtypeHandler,
    QueryContext,
    StaticResponseHandler,
)


def _get_cookie(qctx: QueryContext):
    for o in qctx.query.options:
        if o.otype == dns.edns.OptionType.COOKIE:
            cookie = o
            try:
                if len(cookie.server) == 0:
                    cookie.server = b"\x11\x22\x33\x44\x55\x66\x77\x88"
            except AttributeError:  # dnspython<2.7.0 compat
                if len(o.data) == 8:
                    cookie.data *= 2

            return cookie

    return None


def rrset(
    qname: dns.name.Name | str,
    rtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, rtype, rdata)


class RootNSHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["."]
    qtypes = [dns.rdatatype.NS]
    answer = [rrset(".", dns.rdatatype.NS, "a.root-servers.nil.")]
    additional = [rrset("a.root-servers.nil.", dns.rdatatype.A, "10.53.0.3")]


class CookieHandler(DomainHandler):
    domains = ["example."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:

        # Check for client cookie
        cookie = _get_cookie(qctx)

        # If missing cookie entirely, just return SERVFAIL
        if cookie is None:
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            yield DnsResponseSend(qctx.response, authoritative=True)

        # If there is a client cookie, mock BADCOOKIE to trigger
        # the resend loop logic.
        qctx.response.use_edns(options=[cookie])
        qctx.response.set_rcode(dns.rcode.BADCOOKIE)
        yield DnsResponseSend(qctx.response, authoritative=True)


def resend_server() -> AsyncDnsServer:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        RootNSHandler(),
        CookieHandler(),
    )
    return server


def main() -> None:
    resend_server().run()


if __name__ == "__main__":
    main()
