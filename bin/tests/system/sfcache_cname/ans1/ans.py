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


class Tld1Handler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["foo.tld1."]
    qtypes = [dns.rdatatype.A]
    answer = [rrset("foo.tld1.", dns.rdatatype.CNAME, "tld2.")]


class Tld2Handler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["tld2."]
    qtypes = [dns.rdatatype.A]
    answer = [rrset("tld2.", dns.rdatatype.A, "1.2.3.4")]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        Tld1Handler(),
        Tld2Handler(),
    )
    server.run()


if __name__ == "__main__":
    main()
