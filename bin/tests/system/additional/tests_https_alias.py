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

import dns.message
import dns.name

import isctest


def _query_https(ns, qname):
    msg = isctest.query.create(qname, "HTTPS")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.noerror(res)
    return res


def test_https_alias_target_too_many_records(ns3):
    """
    Resolve HTTPS AliasMode records whose targets are already cached, then
    shut named down and check that nothing was leaked.

    The target of alias14 is a 14-record ServiceMode RRset, i.e. more than
    DNS_RDATASET_MAXADDITIONAL.  Following the alias clones the cached
    target RRset into the caller's rdataset, and the subsequent additional
    processing of that RRset fails with DNS_R_TOOMANYRECORDS.  That error
    used to be returned before the clone was disassociated, leaking a
    reference to the cache node and its slab for every such query.

    The target of alias13 is at the limit and is processed normally.
    """
    # Prime the cache with both target RRsets.
    res = _query_https(ns3, "target14.https.example.")
    isctest.check.rr_count_eq(res.answer, 14)
    res = _query_https(ns3, "target13.https.example.")
    isctest.check.rr_count_eq(res.answer, 13)

    for _ in range(3):
        # An error while collecting the additional data must not turn into
        # a failed response (RFC 9460 section 4.2).
        res = _query_https(ns3, "alias14.https.example.")
        expected = dns.message.from_text(""";ANSWER
alias14.https.example. 86400 IN HTTPS 0 target14.https.example.
""")
        isctest.check.rrsets_equal(res.answer, expected.answer)

        # The alias at the limit is followed and its target is included.
        res = _query_https(ns3, "alias13.https.example.")
        expected = dns.message.from_text(""";ANSWER
alias13.https.example. 86400 IN HTTPS 0 target13.https.example.
""")
        isctest.check.rrsets_equal(res.answer, expected.answer)
        target13 = [
            rrset
            for rrset in res.additional
            if rrset.name == dns.name.from_text("target13.https.example.")
        ]
        isctest.check.rr_count_eq(target13, 13)

    # Stop the server and check for leaked references.  A leaked cache
    # rdataset pins the cache database and its memory context, which shows
    # up in named's memory tracking output at exit.
    ns3.stop()
    assert "outstanding memory" not in ns3.log
