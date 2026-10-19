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
from isctest.asyncserver.handlers import SingleResponseHandler
from isctest.asyncserver.matchers import Domain
from isctest.template import ANS3


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def a(owner: str | dns.name.Name, address: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, address)


def ns(owner: str | dns.name.Name, target: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, target)


class PoisonReferralForwarder(SingleResponseHandler):
    matcher = Domain("fwd.hack.")
    authority = [ns("hack.", "ns.fwd.hack.")]
    additional = [a("ns.fwd.hack.", ANS3.ip)]
    rcode = dns.rcode.NOERROR
    authoritative = False


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handlers(PoisonReferralForwarder())
    server.run()


if __name__ == "__main__":
    main()
