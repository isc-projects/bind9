# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import dns.rcode

import isctest


def test_rrl_cached_recursive_nxdomain(ns2):
    query = isctest.query.create("ncache.tld3.", "A", dnssec=False)

    # Prime ns2's negative cache, then query it again to exercise
    # query_checkrrl() with DNS_R_NCACHENXDOMAIN.
    response = isctest.query.udp(
        query, ns2.ip, port=ns2.ports.dns, timeout=5, attempts=3
    )
    assert response.rcode() == dns.rcode.NXDOMAIN

    response = isctest.query.udp(
        query, ns2.ip, port=ns2.ports.dns, timeout=5, attempts=3
    )
    assert response.rcode() == dns.rcode.NXDOMAIN

    ns2.rndc("status")
