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


import dns.flags
import dns.message

import isctest


def test_gluecache_inzone_ns_target(ns1):
    """Exercise the glue cache path where the NS target is authoritative
    in-zone data (not glue below a zone cut).

    When sub.example. is delegated to ns.example. and ns.example. lives
    at the zone apex, qpzone_find returns ISC_R_SUCCESS rather than
    DNS_R_GLUE in glue_nsdname_cb.  The address records are not treated
    as glue and are therefore not included in the additional section of
    the referral.  However, the rdataset returned by qpzone_find is
    associated but never cleaned up, leaking a vecheader reference.

    Query multiple times to exercise both the cache-miss and cache-hit
    paths in glue_nsdname_cb, then shut down named and verify no
    memory was leaked.
    """
    for _ in range(3):
        msg = isctest.query.create("foo.sub.example.", "A")
        msg.flags &= ~dns.flags.RD
        res = isctest.query.udp(msg, "10.53.0.1")

        expected = """;ANSWER
;AUTHORITY
sub.example. 300 IN NS ns.example.
;ADDITIONAL
"""
        expected_msg = dns.message.from_text(expected)

        isctest.check.noerror(res)
        isctest.check.rrsets_equal(res.answer, expected_msg.answer)
        isctest.check.rrsets_equal(res.authority, expected_msg.authority)
        isctest.check.rrsets_equal(res.additional, expected_msg.additional)

    # Stop the server and check for memory leaks in the shutdown log.
    # The leaked vecheader reference will show up as outstanding memory
    # allocations from rdatavec.c in named's memory tracking output.
    ns1.stop()
    assert "outstanding memory" not in ns1.log
