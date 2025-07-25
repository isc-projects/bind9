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

from datetime import timedelta
import time

from dns import rdatatype

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


def is_rrsig_soa(rrset):
    return rrset.rdtype == rdatatype.RRSIG and rrset.covers == rdatatype.SOA


def test_signatures_validity(ns3, templates):
    # check that increasing signatures-validity triggers resigning
    msg = isctest.query.create("siginterval.example.", "AXFR")
    res = isctest.query.tcp(msg, "10.53.0.3")
    before = next(filter(is_rrsig_soa, res.answer))

    templates.render("ns3/named.conf", {"long_sigs": True})
    with ns3.watch_log_from_here() as watcher:
        ns3.reconfigure(log=False)
        watcher.wait_for_line("siginterval.example/IN (signed): sending notifies")

    res = isctest.query.tcp(msg, "10.53.0.3")
    after = next(filter(is_rrsig_soa, res.answer))

    assert after != before

    ns3.rndc("sign siginterval.example", log=False)

    msg = isctest.query.create("siginterval.example.", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.3")
    sexp = res.answer[-1][0].expiration

    msg = isctest.query.create("siginterval.example.", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.3")
    kexp = res.answer[-1][0].expiration

    delta = timedelta(seconds=kexp - sexp)
    assert delta > timedelta(days=54)


def test_signatures_validity_hours_vs_days():
    # zone configured with 'signatures-validity 500d; signatures-refresh 1d'
    msg = isctest.query.create("hours-vs-days.", "AXFR")
    res = isctest.query.tcp(msg, "10.53.0.2")

    # 499 days in the future w/ a 20 minute runtime to now allowance
    future = timedelta(days=499) - timedelta(minutes=20)
    minimum = time.time() + future.total_seconds()
    for rrset in res.answer:
        if rrset.rdtype != rdatatype.RRSIG:
            continue
        assert rrset[0].expiration >= minimum


def test_nsec_chain():
    # check that NSEC records are properly generated when DNSKEYs
    # are added by dnssec-policy
    msg = isctest.query.create("auto-nsec.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    assert [a for a in res.authority if a.rdtype == rdatatype.NSEC]


def test_nsec3_chain():
    # check that NSEC3 records are properly generated when DNSKEYs
    # are added by dnssec-policy
    msg = isctest.query.create("auto-nsec3.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    assert [a for a in res.authority if a.rdtype == rdatatype.NSEC3]
