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

import os
import re

from dns import edns

import pytest

import isctest


pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.bk",
        "*/*.conf",
        "*/*.db",
        "*/*.id",
        "*/*.jnl",
        "*/*.jbk",
        "*/*.key",
        "*/*.signed",
        "*/settime.out.*",
        "ans*/ans.run",
        "*/trusted.keys",
        "*/*.bad",
        "*/*.next",
        "*/*.stripped",
        "*/*.tmp",
        "*/*.stage?",
        "*/*.patched",
        "*/*.lower",
        "*/*.upper",
        "*/*.unsplit",
    ]
)


def test_tat_queries(ns1, ns6):
    # check that trust-anchor-telemetry queries are logged
    with ns6.watch_log_from_start() as watcher:
        watcher.wait_for_line("sending trust-anchor-telemetry query '_ta-")

    # check that _ta-XXXX trust-anchor-telemetry queries are logged
    with ns1.watch_log_from_start() as watcher:
        watcher.wait_for_line("trust-anchor-telemetry '_ta-")

    # check that _ta-AAAA trust-anchor-telemetry are not sent when disabled
    ns1.log.prohibit("sending trust-anchor-telemetry query '_ta")

    # check that KEY-TAG (ednsopt 14) trust-anchor-telemetry queries are
    # logged. this matches "dig . dnskey +ednsopt=KEY-TAG:ffff":
    msg = isctest.query.create(".", "DNSKEY")
    opt = edns.GenericOption(14, b"\xff\xff")
    msg.use_edns(edns=True, options=[opt])
    pattern = re.compile("trust-anchor-telemetry './IN' from .* 65535")
    with ns1.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, "10.53.0.1")
        watcher.wait_for_line(pattern)

    # check that multiple KEY-TAG trust-anchor-telemetry options don't
    # leak memory, by stopping and restarting the server (a memory leak
    # would trigger a core dump).
    msg = isctest.query.create(".", "DNSKEY")
    opt1 = edns.GenericOption(14, b"\xff\xff")
    opt2 = edns.GenericOption(14, b"\xff\xfe")
    msg.use_edns(edns=True, options=[opt2, opt1])
    pattern = re.compile("trust-anchor-telemetry './IN' from .* 65534")
    with ns1.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, "10.53.0.1")
        isctest.check.noerror(res)
        watcher.wait_for_line(pattern)

    ns1.stop()
    with ns1.watch_log_from_here() as watcher:
        ns1.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line("all zones loaded")
