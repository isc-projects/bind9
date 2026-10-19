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
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import Domain, LabelPredicate, Qname


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def get_dname_rrset_at_name(
    zone: dns.zone.Zone, name: dns.name.Name
) -> dns.rrset.RRset:
    node = zone.get_node(name)
    assert node
    dname = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNAME)
    assert dname
    dname_rrset = dns.rrset.RRset(name, dname.rdclass, dname.rdtype)
    dname_rrset.update(dname)
    return dname_rrset


class ThenDnameLabel(LabelPredicate):
    """
    Match queries whose label right under example.broken. ends with
    "-then-dname".
    """

    def __init__(self) -> None:
        super().__init__(
            -4,
            lambda label: label.endswith(b"-then-dname"),
            'ending with "-then-dname"',
        )


class CnameThenDnameHandler(ResponseHandler):
    """
    For certain trigger QNAMEs, insert a DNAME RRset after the CNAME chain
    prepared from zone data.
    """

    matcher = Domain("example.broken.") & ThenDnameLabel()

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        assert qctx.zone
        last_cname = qctx.response.answer[-1]
        assert last_cname.rdtype == dns.rdatatype.CNAME
        dname_owner = last_cname.name.parent()
        dname_rrset = get_dname_rrset_at_name(qctx.zone, dname_owner)
        qctx.response.answer.append(dname_rrset)
        yield DnsResponseSend(qctx.response)


class DnameOwnerWithoutAuthorityHandler(ResponseHandler):
    """
    Answer at the DNAME owner from zone data, with the authority section
    stripped.
    """

    matcher = Qname("self.example.dname.")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        del qctx.response.authority[:]
        qctx.response.set_rcode(dns.rcode.NOERROR)
        yield DnsResponseSend(qctx.response)


class CnameToDnameOwnerHandler(ResponseHandler):
    """
    Attempt to trigger the resolver variant of CVE-2021-25215.  A `named`
    instance cannot be used for serving the DNAME records returned by this
    response handler as a version of BIND 9 vulnerable to CVE-2021-25215 would
    crash while answering the queries sent by the tested resolver.
    """

    matcher = Domain("self.example.dname.") & ~Qname("self.example.dname.")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        assert qctx.zone
        dname_owner = self.matcher.of(Domain).matched_domain
        del qctx.response.authority[:]
        qctx.response.set_rcode(dns.rcode.NOERROR)
        qctx.response.answer.append(get_dname_rrset_at_name(qctx.zone, dname_owner))
        cname_rrset = rrset(
            qctx.qname, dns.rdatatype.CNAME, dname_owner.to_text(), ttl=60
        )
        qctx.response.answer.append(cname_rrset)
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(acknowledge_manual_dname_handling=True, default_aa=True)
    server.install_response_handlers(
        CnameThenDnameHandler(),
        CnameToDnameOwnerHandler(),
        DnameOwnerWithoutAuthorityHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
