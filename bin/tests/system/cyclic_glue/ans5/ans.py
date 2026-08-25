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

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer, QnameQtypeHandler, StaticResponseHandler


def rrset(
    qname: dns.name.Name | str,
    rtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, rtype, rdata)


def ns(owner: str, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)


def a(owner: str, address: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, address)


class BrokenFooHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["a.foo.test."]
    qtypes = [dns.rdatatype.A]
    authority = [
        ns("foo.test.", "ns.foo.test."),
        ns("foo.test.", "ns.bar.test."),
        ns("foo.test.", "ns.test2."),
    ]
    additional = [
        a("ns.foo.test.", "10.53.0.3"),
        # These glues don't belong, as they're outside the
        # delegated domain. However, only the latest will be
        # ignored by the resolver (the former, being a sibling
        # glue, is still used.)
        a("ns.bar.test.", "10.53.0.3"),
        a("ns.test2.", "10.10.10.10"),
    ]


class BrokenBarHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["a.bar.test."]
    qtypes = [dns.rdatatype.A]
    authority = [
        ns("bar.test.", "ns.bar.test."),
        # This NS is valid but outside the bar.test domain.
        ns("bar.test.", "ns2.foo.test."),
        # This NS is wrong, it's not the qname.
        # It will be ignored by the resolver.
        ns("bar.test2.", "ns.test2."),
    ]
    additional = [
        a("ns.bar.test.", "10.53.0.3"),
        a("ns2.foo.test.", "10.53.0.4"),
        # The glue is then ignored as well, as it doesn't match
        # any of the valid NS above.
        a("ns.test2.", "10.10.10.10"),
    ]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(BrokenFooHandler(), BrokenBarHandler())
    server.run()


if __name__ == "__main__":
    main()
