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

from re import compile as Re
from socket import AF_INET, SOCK_DGRAM, socket

import isctest


def run_attack(ns, name1, type1, name2, type2):
    msg1 = isctest.query.create(name1, type1, cd=True)
    msg2 = isctest.query.create(name2, type2, cd=True)
    port = int(isctest.vars.ALL["PORT"])

    with socket(AF_INET, SOCK_DGRAM) as sock:
        # The order the request does out doesn't matter. What is important is
        # the first query starts recursion before the second query returns the
        # answer, and the second query returns the answer before the first
        # query returns the answer. (So, when the NOERROR/NODATA cames back
        # from the first query, the cache is queried and we get the positive
        # response cached from the second query attached to the fresp rdataset
        # of the response of the first query.)
        # Therefore, the logic is really baked into ans2, which has a 3 seconds
        # delay to answer the first query.
        sock.sendto(msg1.to_wire(), (ns.ip, port))
        sock.sendto(msg2.to_wire(), (ns.ip, port))

    # The second query come back immediately, the resolver caches the DNAME.
    # The first query  come back after 3s (because of intentional ans2 latency
    # on foo.test./DNAME answer) and should not crash the server.
    with ns.watch_log_from_start(timeout=15) as watcher:
        watcher.wait_for_sequence(
            [
                Re(r"foo\.test\..*IN\s+SOA\s+ns\.test\.\s+op\.ns\.test\."),
            ]
        )


def test_dname_negcache(ns3):
    run_attack(ns3, "foo.test.", "DNAME", "a.foo.test.", "A")


def test_cname_negcache(ns3):
    run_attack(ns3, "cname.foo.test.", "CNAME", "cname.foo.test.", "A")
