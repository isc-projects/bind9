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

from isctest.asyncserver import AsyncDnsServer
from isctest.asyncserver.handlers import IgnoreAllQueries, SingleResponseHandler
from isctest.asyncserver.matchers import Qname
from isctest.template import NS3

NAME = "below.www.example.com."


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class FooInfoHandler(IgnoreAllQueries):
    matcher = Qname("foo.info.")


class FallbackHandler(SingleResponseHandler):
    authority = [rrset(NAME, dns.rdatatype.NS, f"ns.{NAME}")]
    additional = [rrset(f"ns.{NAME}", dns.rdatatype.A, NS3.ip)]


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(FooInfoHandler(), FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
