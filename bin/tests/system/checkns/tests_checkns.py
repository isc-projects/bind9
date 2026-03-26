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


import isctest


def test_checkns(ns1):
    with ns1.watch_log_from_start() as watcher:
        watcher.wait_for_line("all zones loaded")

        assert "zone example/IN/vwarn: has no NS records" in ns1.log
        assert "example/IN/vwarn: loaded" in ns1.log
        msg = isctest.query.create("a.example", "A")
        res = isctest.query.udp(msg, ns1.ip, source=ns1.ip)
        isctest.check.noerror(res)

        assert "example2/IN/vignore: loaded" in ns1.log
        assert "has no NS records (example2)" not in ns1.log
        msg = isctest.query.create("a.example2", "A")
        res = isctest.query.udp(msg, ns1.ip, source="10.53.0.2")
        isctest.check.noerror(res)

        assert "zone example3/IN/vfail: has no NS records" in ns1.log
        msg = isctest.query.create("a.example3", "A")
        res = isctest.query.udp(msg, ns1.ip, source="10.53.0.3")
        isctest.check.servfail(res)
