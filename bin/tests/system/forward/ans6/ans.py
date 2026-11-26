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
import dns.rrset

from isctest.asyncserver import (
    ControllableAsyncDnsServer,
    QueryContext,
    ResponseHandler,
)
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.commands import ToggleResponsesCommand
from isctest.asyncserver.handlers import SingleResponseHandler
from isctest.asyncserver.matchers import Domain, Qname, Qtype
from isctest.template import NS2

from ..forward_ans import rrset

SLD = "sld.tld."
NS1 = f"ns1.{SLD}"


def a(owner: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, NS2.ip)


def aaaa(owner: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.AAAA, NS2.ip6)


def ns(owner: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NS, NS1)


def soa(owner: dns.name.Name | str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.SOA, ". . 0 0 0 0 0")


class SldDelegationHandler(ResponseHandler):
    """
    Delegate every NS query at or below sld.tld. to ns1.sld.tld., copying the
    owner name from the QNAME.  Together with Ns1AHandler / Ns1AaaaHandler
    (which resolve the delegated nameserver) and NegativeSoaHandler (the
    negative catch-all), this drives named's DS-chasing logic.
    """

    matcher = Domain(SLD) & Qtype(dns.rdatatype.NS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.use_edns(None)
        qctx.response.answer.append(ns(qctx.qname))
        yield DnsResponseSend(qctx.response)


class Ns1AHandler(SingleResponseHandler):
    matcher = Qname(NS1) & Qtype(dns.rdatatype.A)
    answer = [a(NS1)]
    edns = None


class Ns1AaaaHandler(SingleResponseHandler):
    matcher = Qname(NS1) & Qtype(dns.rdatatype.AAAA)
    answer = [aaaa(NS1)]
    edns = None


class NegativeSoaHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.use_edns(None)
        qctx.response.authority.append(soa(qctx.qname))
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_rcode=dns.rcode.NOERROR, default_aa=True
    )
    server.install_control_command(ToggleResponsesCommand())
    server.install_response_handlers(
        SldDelegationHandler(),
        Ns1AHandler(),
        Ns1AaaaHandler(),
    )
    server.install_response_handlers(NegativeSoaHandler())
    server.run()


if __name__ == "__main__":
    main()
