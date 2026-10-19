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
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import QueryContext, ResponseHandler
from isctest.asyncserver.actions import DnsResponseSend


def rrset(
    owner: str | dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rdtype, rdata)


class AttackNsecHandler(ResponseHandler):
    """
    Answer an NSEC query with a forged NSEC owned by the query name, under an
    RRSIG naming the zone as signer but a key tag no key of the zone has, so
    that the resolver neither verifies nor fails it.
    """

    nsec: str
    key_tag: int

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)
        nsec_rrset = rrset(qctx.qname, dns.rdatatype.NSEC, self.nsec)
        qctx.response.answer.append(nsec_rrset)
        rrsig = qctx.sign(nsec_rrset, bogus=True)[0].replace(key_tag=self.key_tag)
        qctx.response.answer.append(
            dns.rrset.from_rdata(nsec_rrset.name, nsec_rrset.ttl, rrsig)
        )
        yield DnsResponseSend(qctx.response, authoritative=True)
