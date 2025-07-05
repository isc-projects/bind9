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


def test_misconfigured_validation():
    # check that validation fails with a misconfigured trust anchor
    msg = isctest.query.create("example.", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)


def test_misconfigured_negative_validation():
    # check that negative validation fails with a misconfigured trust anchor
    msg = isctest.query.create("example.", "PTR")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)


def test_misconfigured_insecurity():
    # check that insecurity proofs fail with a misconfigured trust anchor
    msg = isctest.query.create("a.insecure.example.", "A")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)


def test_misconfigured_cd_positive():
    # check AD bit of a positive answer with misconfigured trust anchor, CD=1
    msg = isctest.query.create("example.", "SOA")
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res)
    assert (res.flags & flags.AD) == 0


def test_misconfigured_cd_negative():
    # check cd bit on a negative answer with misconfigured trust anchor, CD=1
    msg = isctest.query.create("q.example.", "SOA")
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.nxdomain(res)
    assert (res.flags & flags.AD) == 0
    # compare the response from a correctly configured server
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res2)
    assert (res2.flags & flags.AD) == 0
    assert res.answer == res2.answer


def test_misconfigured_cd_bogus():
    # check cd bit on a query that should fail
    msg = isctest.query.create("a.bogus.example.", "SOA")
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res)
    assert (res.flags & flags.AD) == 0
    # compare the response from a correctly configured server
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res2)
    assert (res2.flags & flags.AD) == 0
    assert res.answer == res2.answer


def test_misconfigured_cd_insecurity():
    # check cd bit on an insecurity proof
    msg = isctest.query.create("a.insecure.example.", "SOA")
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res)
    assert (res.flags & flags.AD) == 0
    # compare the response from a correctly configured server
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res2)
    assert (res2.flags & flags.AD) == 0
    assert res.answer == res2.answer


def test_misconfigured_cd_negative_insecurity():
    # check cd bit on an insecurity proof
    msg = isctest.query.create("q.insecure.example.", "A")
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.nxdomain(res)
    assert (res.flags & flags.AD) == 0
    # compare the response from a correctly configured server
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res2)
    assert (res2.flags & flags.AD) == 0
    assert res.answer == res2.answer


def test_revoked_init(servers, templates):
    # use a revoked key and try to reiniitialize; check for failure
    ns5 = servers["ns5"]
    templates.render("ns5/named.conf", {"revoked_key": True})
    ns5.reconfigure(log=False)

    msg = isctest.query.create(".", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)


def test_broken_forwarding(servers, templates):
    # check forwarder CD behavior (forward server with bad trust anchor)
    ns5 = servers["ns5"]
    templates.render("ns5/named.conf", {"broken_key": True})
    ns5.reconfigure(log=False)

    ns9 = servers["ns9"]
    templates.render("ns9/named.conf", {"forward_badkey": True})
    ns9.reconfigure(log=False)

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
