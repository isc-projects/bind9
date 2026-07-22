# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.

import isctest


def query(ns, name):
    msg = isctest.query.create(name, "DNAME")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.noerror(res)
    isctest.check.has_answer(res)


# Regression test for CVE-2021-25215.
def test_chain_dname_self_resolution(ns2, ns7):
    # Checking DNAME resolution via itself (authoritative).
    query(ns2, "self.domain0.self.domain0.nil.")

    # Checking DNAME resolution via itself (recursive).
    query(ns7, "self.example.self.example.dname.")

    # Checking DNAME resolution via itself (resolver cache).
    query(ns7, "self.example.self.example.dname.")
