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

from dns import flags

import pytest

import isctest


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns5, ns9, templates):
    templates.render("ns5/named.conf", {"broken_key": True})
    ns5.reconfigure(log=False)

    templates.render("ns9/named.conf", {"forward_badkey": True})
    ns9.reconfigure(log=False)


def test_broken_forwarding(ns9):
    # check forwarder CD behavior (forward server with bad trust anchor)

    # confirm invalid trust anchor produces SERVFAIL in resolver
    msg = isctest.query.create("a.secure.example.", "A")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)

    # check that lookup involving forwarder succeeds and SERVFAIL was received
    with ns9.watch_log_from_here() as watcher:
        msg = isctest.query.create("a.secure.example.", "SOA")
        res = isctest.query.tcp(msg, "10.53.0.9")
        isctest.check.noerror(res)
        assert (res.flags & flags.AD) != 0
        watcher.wait_for_line("status: SERVFAIL")
