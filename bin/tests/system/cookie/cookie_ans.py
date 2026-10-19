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

import abc

import dns.edns
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsProtocol,
    QueryContext,
    ResponseHandler,
)
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.matchers import LabelCount, LeftmostLabel, Protocol, Qtype
from isctest.name import prepend_label
from isctest.template import ANS9, ANS10
from isctest.vars.algorithms import ALG_VARS

KEYRING = dns.tsigkeyring.from_text(
    {
        "foo": (ALG_VARS["DEFAULT_HMAC"], "aaaaaaaaaaaa"),
        "fake": (ALG_VARS["DEFAULT_HMAC"], "aaaaaaaaaaaa"),
    }
)


def add_cookie(qctx: QueryContext) -> None:
    for o in qctx.query.options:
        if o.otype == dns.edns.OptionType.COOKIE:
            cookie = o
            if len(cookie.server) == 0:
                cookie.server = cookie.client

            qctx.response.use_edns(options=[cookie])
            return


def tld(qctx: QueryContext) -> dns.name.Name:
    return dns.name.Name(qctx.qname.labels[-2:])


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 1,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def soa(qctx: QueryContext) -> dns.rrset.RRset:
    return rrset(tld(qctx), dns.rdatatype.SOA, ". . 0 0 0 0 2", ttl=2)


def ns_name(qctx: QueryContext) -> dns.name.Name:
    return prepend_label("ns", tld(qctx))


def ns(qctx: QueryContext) -> dns.rrset.RRset:
    return rrset(qctx.qname, dns.rdatatype.NS, ns_name(qctx).to_text())


def legit_a(qctx: QueryContext) -> dns.rrset.RRset:
    return rrset(qctx.qname, dns.rdatatype.A, ANS9.ip)


def spoofed_a(qctx: QueryContext) -> dns.rrset.RRset:
    return rrset(qctx.qname, dns.rdatatype.A, ANS10.ip)


class _SpoofableHandler(ResponseHandler, abc.ABC):
    def __init__(self, evil_server: bool) -> None:
        self.evil_server = evil_server


class NsHandler(_SpoofableHandler):
    matcher = Qtype(dns.rdatatype.NS) & LabelCount(2)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.answer.append(ns(qctx))
        if self.evil_server:
            qctx.response.authority.append(spoofed_a(qctx))
        else:
            qctx.response.authority.append(legit_a(qctx))
        yield DnsResponseSend(qctx.response)


class GlueHandler(_SpoofableHandler):
    matcher = Qtype(dns.rdatatype.A) & LabelCount(3) & LeftmostLabel(b"ns")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        if self.evil_server:
            qctx.response.answer.append(spoofed_a(qctx))
        else:
            qctx.response.answer.append(legit_a(qctx))
        yield DnsResponseSend(qctx.response)


class CookielessTcpAHandler(ResponseHandler):
    matcher = (
        Qtype(dns.rdatatype.A) & Protocol(DnsProtocol.TCP) & LeftmostLabel(b"nocookie")
    )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(legit_a(qctx))
        yield DnsResponseSend(qctx.response)


class TcpAHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.A) & Protocol(DnsProtocol.TCP)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.answer.append(legit_a(qctx))
        yield DnsResponseSend(qctx.response)


class WithtsigUdpAHandler(ResponseHandler):
    matcher = (
        Qtype(dns.rdatatype.A) & Protocol(DnsProtocol.UDP) & LeftmostLabel(b"withtsig")
    )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(legit_a(qctx))
        qctx.response.answer.append(spoofed_a(qctx))
        qctx.response.use_tsig(keyring=KEYRING, keyname="fake")
        yield DnsResponseSend(qctx.response)

        qctx.prepare_new_response()
        add_cookie(qctx)
        qctx.response.answer.append(legit_a(qctx))
        yield DnsResponseSend(qctx.response)


class SpoofedUdpAHandler(ResponseHandler):
    matcher = (
        Qtype(dns.rdatatype.A)
        & Protocol(DnsProtocol.UDP)
        & LeftmostLabel(b"nocookie", b"tcponly")
    )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(legit_a(qctx))
        qctx.response.answer.append(spoofed_a(qctx))
        yield DnsResponseSend(qctx.response)


class UdpAHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.A) & Protocol(DnsProtocol.UDP)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(legit_a(qctx))
        add_cookie(qctx)
        yield DnsResponseSend(qctx.response)


class FallbackSoaHandler(ResponseHandler):
    matcher = Qtype(dns.rdatatype.SOA)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.answer.append(soa(qctx))
        yield DnsResponseSend(qctx.response)


class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        add_cookie(qctx)
        qctx.response.authority.append(soa(qctx))
        yield DnsResponseSend(qctx.response)


def cookie_server(evil: bool) -> AsyncDnsServer:
    server = AsyncDnsServer(
        keyring=KEYRING, default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    server.install_response_handlers(
        CookielessTcpAHandler(),
        FallbackSoaHandler(),
        GlueHandler(evil),
        NsHandler(evil),
        SpoofedUdpAHandler(),
        WithtsigUdpAHandler(),
    )
    server.install_response_handlers(
        TcpAHandler(),
        UdpAHandler(),
    )
    server.install_response_handlers(FallbackHandler())
    return server
