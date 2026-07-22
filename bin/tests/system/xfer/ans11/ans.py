"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator

import dns.flags
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    AxfrHandler,
    DnsProtocol,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
    StaticResponseHandler,
)

ZONE = "ixfr-race."
NS_NAME = f"ns.{ZONE}"
NUM_RECORDS = 400


def rrset(
    owner: str, ttl: int, rdtype: dns.rdatatype.RdataType, rdata: str
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


def soa(serial: int) -> dns.rrset.RRset:
    return rrset(
        ZONE,
        3600,
        dns.rdatatype.SOA,
        f"{NS_NAME} admin.{ZONE} {serial} 3600 900 604800 86400",
    )


def a(owner: str, address: str) -> dns.rrset.RRset:
    return rrset(owner, 3600, dns.rdatatype.A, address)


def ns() -> dns.rrset.RRset:
    return rrset(ZONE, 3600, dns.rdatatype.NS, NS_NAME)


def host_a_records(second_octet: int) -> list[dns.rrset.RRset]:
    return [
        a(f"host-{i}.{ZONE}", f"10.{second_octet}.{(i >> 8) & 0xFF}.{i & 0xFF}")
        for i in range(NUM_RECORDS)
    ]


def ixfr_diff() -> list[dns.rrset.RRset]:
    """
    Craft the answer of a valid IXFR diff (serial 1 -> 3) whose trailing
    boundary SOA triggers ixfr_commit() on the receiving secondary.

    The sections are, in order: end SOA (serial 3), old SOA (serial 1) opening
    the deletions, the deleted A records, the mid SOA (serial 2) opening the
    additions, the added A records, and finally the boundary SOA (serial 2)
    which drives ixfr_commit() and enqueues the diff-applying worker thread.
    """
    return [
        soa(3),
        soa(1),
        *host_a_records(0),
        soa(2),
        *host_a_records(1),
        soa(2),
    ]


class TransferState:
    """
    Flag toggled once the initial AXFR (serial 1) has been served.  The SOA
    handlers read it to advertise serial 1 before the transfer and serial 3
    after it, so the secondary's next refresh switches from AXFR to IXFR.
    """

    def __init__(self) -> None:
        self.initial_axfr_served = False


class TransferHandler(ResponseHandler):
    """Base for the handlers that share a single TransferState."""

    def __init__(self, progress: TransferState) -> None:
        super().__init__()
        self._progress = progress


class InitialSoaHandler(TransferHandler, StaticResponseHandler):
    answer = [soa(1)]

    def match(self, qctx: QueryContext) -> bool:
        return (
            qctx.qtype == dns.rdatatype.SOA and not self._progress.initial_axfr_served
        )


class RefreshSoaHandler(TransferHandler, StaticResponseHandler):
    answer = [soa(3)]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.SOA and self._progress.initial_axfr_served


class InitialAxfrHandler(TransferHandler, AxfrHandler):
    """Serve the initial zone (serial 1) and mark the transfer as done."""

    initial_soa = soa(1)
    zone_contents = [
        ns(),
        a(NS_NAME, "127.0.0.1"),
        *host_a_records(0),
    ]
    final_soa = soa(1)

    def match(self, qctx: QueryContext) -> bool:
        matched = super().match(qctx)
        if matched:
            self._progress.initial_axfr_served = True
        return matched


class TruncatedIxfrHandler(ResponseHandler):
    """Set TC on an IXFR received over UDP to force the secondary to retry over TCP."""

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.IXFR and qctx.protocol == DnsProtocol.UDP

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.flags |= dns.flags.TC
        yield DnsResponseSend(qctx.response)


class RaceIxfrHandler(ResponseHandler):
    """
    Reproduce the IXFR->AXFR use-after-free race (GL#5767).

    Over TCP, send a large valid IXFR diff whose boundary SOA triggers
    ixfr_commit() and enqueues a diff-applying worker thread, immediately
    followed by a SERVFAIL response that makes xfrin_recv_done() fall through to
    try_axfr() -> xfrin_reset(), tearing down the journal/version while that
    worker is still running.
    """

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.IXFR and qctx.protocol == DnsProtocol.TCP

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        for rrset_ in ixfr_diff():
            qctx.response.answer.append(rrset_)
        yield DnsResponseSend(qctx.response)

        qctx.prepare_new_response(with_zone_data=False)
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    progress = TransferState()
    server.install_response_handlers(
        InitialSoaHandler(progress),
        RefreshSoaHandler(progress),
        InitialAxfrHandler(progress),
        TruncatedIxfrHandler(),
        RaceIxfrHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
