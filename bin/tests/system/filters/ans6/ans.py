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
from isctest.asyncserver.handlers import IgnoreAllQueries, StaticResponseHandler
from isctest.asyncserver.matchers import FirstN, Once, Qname, Qtype

DNS64_TRIGGER = "nodata.test."


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    *rdata: str,
    ttl: int = 60,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, *rdata)


def soa() -> dns.rrset.RRset:
    return rrset(
        "test.", dns.rdatatype.SOA, "ns.test. hostmaster.test. 1 2 3 4 1", ttl=1
    )


def a() -> dns.rrset.RRset:
    return rrset(DNS64_TRIGGER, dns.rdatatype.A, "192.0.2.1")


def aaaa() -> dns.rrset.RRset:
    return rrset(DNS64_TRIGGER, dns.rdatatype.AAAA, "2001:db8::1")


class IgnoreFirstTwoAHandler(IgnoreAllQueries):
    """
    Leave the resolver's first two A queries unanswered, so that the A answer
    arrives after the one-second NODATA has expired.  This relies on named
    waiting at least 1.2 seconds for an answer from a forwarder before it
    retries: its third A query comes at least 2.4 seconds after the NODATA.
    The test fails if the NODATA has not expired by then.

    Delaying the A answer instead does not work: named discards an answer
    that arrives after it has given up on the query.
    """

    matcher = FirstN(2, Qname(DNS64_TRIGGER) & Qtype(dns.rdatatype.A))


class NodataOnceHandler(StaticResponseHandler):
    """
    Answer only the first AAAA query, with NODATA, so the DNS64 resolver looks
    up an A record.  If the NODATA expires from the cache before the A answer
    arrives, filter-a re-enters and re-queries AAAA (answered by AaaaHandler),
    triggering the bug.
    """

    matcher = Once(Qname(DNS64_TRIGGER) & Qtype(dns.rdatatype.AAAA))
    authority = [soa()]


class AHandler(StaticResponseHandler):
    matcher = Qname(DNS64_TRIGGER) & Qtype(dns.rdatatype.A)
    answer = [a()]


class AaaaHandler(StaticResponseHandler):
    matcher = Qname(DNS64_TRIGGER) & Qtype(dns.rdatatype.AAAA)
    answer = [aaaa()]


class FallbackHandler(StaticResponseHandler):
    rcode = dns.rcode.NXDOMAIN
    authority = [soa()]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        IgnoreFirstTwoAHandler(),
        NodataOnceHandler(),
    )
    server.install_response_handlers(
        AHandler(),
        AaaaHandler(),
    )
    server.install_response_handlers(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
