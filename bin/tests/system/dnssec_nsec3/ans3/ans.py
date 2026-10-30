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

from isctest.asyncserver import AsyncDnsServer, QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.handlers import StaticResponseHandler
from isctest.asyncserver.matchers import Qname, Qtype

from ..dnssec_nsec3_ans import minimal_covering_nsec3, rrset


def a(owner: str | dns.name.Name, address: str = "192.0.2.55") -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, address)


class ControlAHandler(StaticResponseHandler):
    """
    This handler imitates successfully spoofing an unsigned response to an
    "a.ctl.f055.test/A" query sent to a server authoritative for the
    "f055.test." domain.  The subsequent "ctl.f055.test/DS" query sent by the
    resolver is responded to with a properly signed NODATA response prepared
    from zone data.  These two responses combined demonstrate that named
    refuses to treat an unsigned answer to the A query as legitimate when the
    DS non-existence proof is properly signed.
    """

    matcher = Qname("a.ctl.f055.test.") & Qtype(dns.rdatatype.A)
    answer = [a(matcher.of(Qname).qnames[0])]


class AttackAHandler(StaticResponseHandler):
    """
    This handler imitates successfully spoofing an unsigned response to an
    "a.cut.f055.test/A" query sent to a server authoritative for the
    "f055.test." domain.  The subsequent "cut.f055.test/DS" query sent by the
    resolver is responded to by AttackDsHandler, which makes a vulnerable
    resolver treat an unsigned answer to the A query as a legitimate insecure
    response.
    """

    matcher = Qname("a.cut.f055.test.") & Qtype(dns.rdatatype.A)
    answer = [a(matcher.of(Qname).qnames[0])]


class AttackDsHandler(ResponseHandler):
    """
    This handler imitates successfully spoofing a response to a
    "cut.f055.test/DS" query sent to a server authoritative for the
    "f055.test." domain.  The spoofed response contains a properly signed
    zone-based NODATA response (which can be replayed by an attacker) with an
    extra forged NSEC3 record also proving that the DS record does not exist,
    but accompanied by a bogus RRSIG record.  A vulnerable resolver treats such
    a broken non-existence proof as sufficient for returning an unsigned answer
    to the A query to the client.
    """

    matcher = Qname("cut.f055.test.") & Qtype(dns.rdatatype.DS)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        assert qctx.zone
        assert qctx.zone.origin
        forged_nsec3_covering_rrset = minimal_covering_nsec3(
            qctx.qname, qctx.zone.origin, opt_out=True
        )
        forged_nsec3_covering_rrsig = qctx.sign(forged_nsec3_covering_rrset, bogus=True)
        qctx.response.authority.append(forged_nsec3_covering_rrset)
        qctx.response.authority.append(forged_nsec3_covering_rrsig)

        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ControlAHandler(),
        AttackAHandler(),
        AttackDsHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
