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

import threading
import time

import dns.edns
import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
    ]
)


def _toggle(mode: str) -> None:
    msg = isctest.query.create(f"{mode}.send-responses._control.", "TXT", dnssec=False)
    isctest.query.udp(msg, "10.53.0.3", attempts=1)


def test_no_stale_data_times_out():
    """Verify the resolver does not answer until the query timeout.

    With the authoritative server unresponsive and the queried name
    absent from the cache, dig must time out instead of receiving a
    fast SERVFAIL (the original test 120 in serve_stale/tests.sh).
    """

    _toggle("disable")
    msg = isctest.query.create("notincache.example.", "TXT", dnssec=False)
    start = time.monotonic()
    with pytest.raises(dns.exception.Timeout):
        isctest.query.udp(msg, "10.53.0.2", timeout=3, attempts=1)
    assert time.monotonic() - start >= 3


def test_servfail_with_ede22():
    """Verify SERVFAIL carries EDE 22 (and not EDE 3) when auth is unreachable.

    With the authoritative server unresponsive and no cached data to
    serve stale, the resolver must return SERVFAIL with EDE 22 (No
    Reachable Authority) and must not attach EDE 3 (Stale Answer)
    (the original test 125 in serve_stale/tests.sh).
    """

    _toggle("disable")
    msg = isctest.query.create("notfound.example.", "TXT", dnssec=False)
    res = isctest.query.udp(msg, "10.53.0.2", timeout=15, attempts=1)
    isctest.check.servfail(res)
    isctest.check.ede(res, dns.edns.EDECode.NO_REACHABLE_AUTHORITY)
    assert not any(
        opt.otype == dns.edns.OptionType.EDE
        and opt.code == dns.edns.EDECode.STALE_ANSWER
        for opt in res.options
    ), "unexpected stale-answer EDE in SERVFAIL response"
    assert len(res.answer) == 0


def test_authoritative_answer_after_reenable():
    """Verify the resolver waits for auth to recover instead of failing fast.

    Prime the cache, let the TTL expire, disable the authoritative
    server, issue a query, and re-enable the authoritative server
    while the query is still in flight.  The resolver must return an
    authoritative NOERROR answer with no EDE attached, not a stale
    answer or SERVFAIL (the original test 163 in serve_stale/tests.sh).
    """

    _toggle("enable")
    msg = isctest.query.create("data.example.", "TXT", dnssec=False)
    isctest.check.noerror(isctest.query.udp(msg, "10.53.0.2", timeout=5))

    # allow the 2s TTL to expire
    time.sleep(3)

    _toggle("disable")

    timer = threading.Timer(1.0, _toggle, args=("enable",))
    timer.start()
    try:
        res = isctest.query.udp(msg, "10.53.0.2", timeout=15, attempts=1)
    finally:
        timer.join()

    isctest.check.noerror(res)
    isctest.check.noede(res)
    answer = res.find_rrset(
        res.answer,
        dns.name.from_text("data.example."),
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
    )
    assert "A text record with a 2 second ttl" in str(answer[0])
