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

import isctest


def test_hooks():
    msg = isctest.query.create("example.com.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    # the test-async plugin changes the status of any positive answer to NOTIMP
    isctest.check.notimp(res)


def test_hooks_noextension(ns1, templates):
    templates.render("ns1/named.conf", {"noextension": True})
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reload")
        watcher.wait_for_line("all zones loaded")
    test_hooks()
