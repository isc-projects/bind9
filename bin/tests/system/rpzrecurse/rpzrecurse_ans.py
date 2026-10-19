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
import dns.rdataclass
import dns.rdatatype
import dns.rrset


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
