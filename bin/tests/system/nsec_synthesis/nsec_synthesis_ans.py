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

import dns.dnssec
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

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.prepare_new_response(with_zone_data=False)

        nsec_rrset = rrset(qctx.qname, dns.rdatatype.NSEC, self.nsec)
        qctx.response.answer.append(nsec_rrset)

        assert qctx.zone and qctx.zone.origin
        dnskeys = qctx.zone.get_rrset(qctx.zone.origin, dns.rdatatype.DNSKEY)
        assert dnskeys
        zone_tags = {dns.dnssec.key_id(dnskey) for dnskey in dnskeys}
        unknown_tag = next((tag for tag in range(65536) if tag not in zone_tags), 0)

        rrsig = qctx.sign(nsec_rrset, bogus=True)[0].replace(key_tag=unknown_tag)
        qctx.response.answer.append(
            dns.rrset.from_rdata(nsec_rrset.name, nsec_rrset.ttl, rrsig)
        )

        yield DnsResponseSend(qctx.response)
