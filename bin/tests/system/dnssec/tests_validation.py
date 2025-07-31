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
import shutil
import time

from dns import edns, flags, name, rdataclass, rdatatype

import pytest

import isctest
import isctest.mark
from isctest.util import param


pytest.importorskip("dns", minversion="2.0.0")
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


# helper functions
def grep_q(regex, filename):
    with open(filename, "r", encoding="utf-8") as f:
        blob = f.read().splitlines()
    results = [x for x in blob if re.search(regex, x)]
    return len(results) != 0


def getfrom(file):
    with open(file, encoding="utf-8") as f:
        return f.read().strip()


@pytest.mark.requires_zones_loaded("ns2", "ns3")
@pytest.mark.parametrize(
    "qname, qtype",
    [
        param("a.example.", "A"),
        param("rfc2535.example.", "SOA"),
    ],
)
def test_load_transfer(qname, qtype):
    # check that we can load and transfer zone
    msg = isctest.query.create(qname, qtype)
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res1)


def test_insecure_glue():
    # check that for a query against a validating resolver where the
    # authoritative zone is unsigned (insecure delegation), glue is returned
    # in the additional section
    msg = isctest.query.create("a.insecure.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.authority, 1)
    isctest.check.rr_count_eq(res.additional, 1)
    assert str(res.additional[0].name) == "ns3.insecure.example."
    addrs = [str(a) for a in res.additional[0]]
    assert "10.53.0.3" in addrs


def test_adflag():
    # compare auth and recursive answers
    msg = isctest.query.create("a.example", "A", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)

    # check no AD flag in authoritative response
    isctest.check.noadflag(res1)

    # check validating resolver sends AD=1 if the client sent AD=1
    isctest.check.adflag(res2)

    # check that AD=0 unless the client sent AD=1
    msg = isctest.query.create("a.example", "A", dnssec=False, ad=False)
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res2)


def test_secure_root(ns4):
    # check that a query for a secure root validates
    msg = isctest.query.create(".", "KEY")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # check that "rndc secroots" dumps the trusted keys
    key = int(getfrom("ns1/managed.key.id"))
    alg = os.environ["DEFAULT_ALGORITHM"]
    expected = f"./{alg}/{key} ; static"
    response = ns4.rndc("secroots -", log=False).splitlines()
    assert expected in response
    assert len(response) == 10


def test_positive_validation_nsec():
    # positive answer
    msg = isctest.query.create("a.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # wildcard
    msg = isctest.query.create("a.wild.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)

    assert str(res2.authority[0].name) == "*.wild.example."
    assert res2.authority[0].rdtype == rdatatype.NSEC
    nsecs = [str(a).split(" ", maxsplit=1)[0] for a in res2.authority[0]]
    assert "z.example." in nsecs
    assert res2.authority[1].rdtype == rdatatype.RRSIG
    assert res2.authority[1].covers == rdatatype.NSEC

    # mixed case
    for rrtype in ["a", "txt", "aaaa", "loc"]:
        msg = isctest.query.create("mixedcase.secure.example", rrtype)
        res1 = isctest.query.tcp(msg, "10.53.0.3")
        res2 = isctest.query.tcp(msg, "10.53.0.4")
        isctest.check.same_answer(res1, res2)
        isctest.check.noerror(res2)
        isctest.check.adflag(res2)


def test_positive_validation_nsec3():
    # positive answer
    msg = isctest.query.create("a.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)

    # wildcard
    msg = isctest.query.create("a.wild.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    isctest.check.rr_count_eq(res2.authority, 4)

    # unknown NSEC3 hash algorithm
    msg = isctest.query.create("nsec3-unknown.example", "SOA", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    isctest.check.rr_count_eq(res2.answer, 1)


def test_positive_validation_optout():
    # positive answer
    msg = isctest.query.create("a.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # wildcard
    msg = isctest.query.create("a.wild.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # unknown NSEC3 hash algorithm
    msg = isctest.query.create("optout-unknown.example", "SOA", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    isctest.check.rr_count_eq(res2.answer, 1)


def answer_has(r, rdtype):
    return bool([r for r in r.answer if r.rdtype == rdtype])


def test_chain_validation():
    # check validation of ANY response
    msg = isctest.query.create("foo.example", "ANY")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 6)  # 2 records, 1 NSEC, 3 RRSIGs

    # check validation of CNAME response
    msg = isctest.query.create("cname1.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 4)  # CNAME, TXT, 2 RRSIGs

    # check validation of DNAME response
    msg = isctest.query.create("foo.dname1.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 5)  # DNAME, TXT, 2 RRSIGs, synth CNAME

    # check validation of CNAME response to ANY query
    msg = isctest.query.create("cname2.example", "ANY")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 4)  # CNAME, NSEC, 2 RRSIGs

    # check validation of DNAME response to ANY query
    msg = isctest.query.create("foo.dname2.example", "ANY")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.rr_count_eq(res2.answer, 3)  # DNAME, RSRIG, synth CNAME

    # check bad CNAME signature is caught after +CD query
    msg = isctest.query.create("bad-cname.example", "A", dnssec=False, cd=True)
    # query once with CD to prime the cache
    res = isctest.query.tcp(msg, "10.53.0.4")
    # query again with CD, bogus pending data should be returned
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    assert "a.example." in str(res.answer[0])
    assert "10.0.0.1" in str(res.answer[1])
    # query again without CD, bogus data should be rejected
    msg = isctest.query.create("bad-cname.example", "A", dnssec=False)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)

    # check bad DNAME signature is caught after +CD query
    msg = isctest.query.create("a.bad-dname.example", "A", dnssec=False, cd=True)
    # query once with CD to prime the cache
    res = isctest.query.tcp(msg, "10.53.0.4")
    # query again with CD, bogus pending data should be returned
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    assert "example." in str(res.answer[0])
    assert "a.example." in str(res.answer[1])
    assert "10.0.0.1" in str(res.answer[2])
    # query again without CD, bogus data should be rejected
    msg = isctest.query.create("a.bad-dname.example", "A", dnssec=False)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)

    # check DNSKEY lookup via CNAME
    msg = isctest.query.create("cnameandkey.secure.example", "DNSKEY")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)
    assert answer_has(res2, rdatatype.CNAME)

    # check KEY lookup via CNAME
    msg = isctest.query.create("cnameandkey.secure.example", "KEY")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)
    assert not answer_has(res2, rdatatype.CNAME)

    # check KEY lookup via CNAME (not present)
    msg = isctest.query.create("cnamenokey.secure.example", "KEY")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)
    assert not answer_has(res2, rdatatype.CNAME)

    # check DNSKEY lookup via DNAME
    msg = isctest.query.create("a.dnameandkey.secure.example", "DNSKEY")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)
    assert answer_has(res2, rdatatype.DNAME)

    # check KEY lookup via DNAME
    msg = isctest.query.create("a.dnameandkey.secure.example", "KEY")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)
    assert answer_has(res2, rdatatype.DNAME)


@isctest.mark.rsasha1
def test_signing_algorithms_rsasha1():
    # rsasha1 (should work with FIPS mode we're as only validating)
    msg = isctest.query.create("a.rsasha1.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # rsasha1 (1024 bits) NSEC
    msg = isctest.query.create("a.rsasha1-1024.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)


def test_signing_algorithms():
    # rsasha256
    msg = isctest.query.create("a.rsasha256.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # rsasha512
    msg = isctest.query.create("a.rsasha512.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # KSK-only DNSKEY
    msg = isctest.query.create("a.kskonly.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)


def test_private_algorithms(ns4):
    # positive answer, private algorithm
    msg = isctest.query.create("a.rsasha256oid.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # positive answer, unknown private algorithm
    msg = isctest.query.create("a.unknownoid.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noadflag(res2)

    # positive answer, extra ds for private algorithm
    msg = isctest.query.create("a.extradsoid.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # positive anwer, extra ds for unknown private algorithm
    with ns4.watch_log_from_here() as watcher:
        msg = isctest.query.create("a.extradsunknownoid.example", "A")
        res1 = isctest.query.tcp(msg, "10.53.0.3")
        res2 = isctest.query.tcp(msg, "10.53.0.4")
        isctest.check.noerror(res1)
        isctest.check.servfail(res2)
        watcher.wait_for_line(
            "No DNSKEY for extradsunknownoid.example/DS with PRIVATEOID"
        )


@isctest.mark.extended_ds_digest
def test_private_algorithms_extended_ds():
    # check positive validation with extra ds using extended digest
    # type for unknown private algorithm
    msg = isctest.query.create("a.extended-ds-unknown-oid.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)


def test_negative_validation_nsec():
    # nxdomain
    msg = isctest.query.create("q.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.adflag(res2)

    # nodata
    msg = isctest.query.create("a.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.empty_answer(res2)
    isctest.check.adflag(res2)

    # negative wildcard
    msg = isctest.query.create("b.wild.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)


def test_negative_validation_nsec3():
    # nxdomain
    msg = isctest.query.create("q.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.adflag(res2)

    # nodata
    msg = isctest.query.create("a.nsec3.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.empty_answer(res2)
    isctest.check.adflag(res2)

    # negative wildcard
    msg = isctest.query.create("b.wild.nsec3.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)

    # check NSEC3 zone with mismatched NSEC3PARAM / NSEC parameters
    msg = isctest.query.create("non-exist.badparam", "A")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.nxdomain(res)

    # check negative unknown NSEC3 hash algorithm does not validate
    msg = isctest.query.create("nsec3-unknown.example", "A", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.servfail(res2)


def test_excessive_nsec3_iterations():
    assert grep_q(
        "zone too-many-iterations/IN: excessive NSEC3PARAM iterations", "ns2/named.run"
    )
    assert grep_q(
        "zone too-many-iterations/IN: excessive NSEC3PARAM iterations", "ns3/named.run"
    )

    # check fallback to insecure with NSEC3 iterations is too high
    msg = isctest.query.create("does-not-exist.too-many-iterations", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noadflag(res2)
    isctest.check.rr_count_eq(res2.answer, 0)
    isctest.check.rr_count_eq(res2.authority, 8)

    # check fallback to insecure with NSEC3 iterations is too high (nodata)
    msg = isctest.query.create("a.too-many-iterations", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noadflag(res2)
    isctest.check.rr_count_eq(res2.answer, 0)
    isctest.check.rr_count_eq(res2.authority, 4)

    # check fallback to insecure with NSEC3 iterations is too high (wildcard)
    msg = isctest.query.create("wild.a.too-many-iterations", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noadflag(res2)
    isctest.check.rr_count_eq(res2.answer, 2)
    isctest.check.rr_count_eq(res2.authority, 4)
    a, _ = res2.answer
    assert str(a.name) == "wild.a.too-many-iterations."
    assert str(a[0]) == "10.0.0.3"

    # check fallback to insecure with high NSEC3 iterations (wildcard nodata)
    msg = isctest.query.create("wild.a.too-many-iterations", 100)
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noadflag(res2)
    isctest.check.rr_count_eq(res2.authority, 8)


def test_auth_nsec3():
    # nxdomain response, closest encloser with 0 empty non-terminals
    msg = isctest.query.create("b.b.b.b.b.a.nsec3.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res)
    # closest encloser (a.nsec3.example):
    rrset = res.get_rrset(
        res.authority,
        name.from_text("6OVDUHTN094ML2PV8AN90U0DPU823GH2.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "NSEC3 missing from AUTHORITY: " + str(res)
    assert "7AT0S0RIDCJRFF2M5H5AAV22CSFJBUL4" in str(rrset[0]).upper()
    # no QNAME (b.a.nsec3.example/DSPF4R9UKOEPJ9O34E1H4539LSOTL14E)
    rrset = res.get_rrset(
        res.authority,
        name.from_text("BEJ5GMQA872JF4DAGQ0R3O5Q7A2O5S9L.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "EF2S05SGK1IR2K5SKMFIRERGQCLMR18M" in str(rrset[0]).upper()
    # no WILDCARD (*.a.nsec3.example/TFGQ60S97BS31IT1EBEDO63ETM0T5JFA)
    rrset = res.get_rrset(
        res.authority,
        name.from_text("R8EVDMNIGNOKME4LH2H90OSP2PRSNJ1Q.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "VH656EQUD4J02OFVSO4GKOK5D02MS1TL" in str(rrset[0]).upper()

    # nxdomain response, closest encloser with 1 ENT
    msg = isctest.query.create("b.b.b.b.b.a.a.nsec3.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res)
    # closest encloser (a.a.nsec3.example):
    rrset = res.get_rrset(
        res.authority,
        name.from_text("NGCJFSOLJUUE27PFNQNJIME4TQ0OU2DH.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "R8EVDMNIGNOKME4LH2H90OSP2PRSNJ1Q" in str(rrset[0]).upper()
    # noqname (b.a.a.nsec3.example):
    rrset = res.get_rrset(
        res.authority,
        name.from_text("R8EVDMNIGNOKME4LH2H90OSP2PRSNJ1Q.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "VH656EQUD4J02OFVSO4GKOK5D02MS1TL" in str(rrset[0]).upper()
    # no wildcard (*.a.a.nsec3.example/V7JNNDJ4NLRIU195FRB7DLUCSLU4LLFM)
    # is covered by the noqname proof in this case

    # nxdomain response, closest encloser with 2 ENTs
    msg = isctest.query.create("b.b.b.b.b.a.a.a.nsec3.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res)
    # closest encloser (a.a.a.nsec3.example):
    rrset = res.get_rrset(
        res.authority,
        name.from_text("H7RHPDCHSVVRAND332F878C8AB6IBJQV.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "K8IG76R2UPQ13IKFO49L7IB9JRVB6QJI" in str(rrset[0]).upper()
    # noqname (b.a.a.a.nsec3.example/18Q8D89RM8GGRSSOPFRB05QS6VEGB1P4)
    rrset = res.get_rrset(
        res.authority,
        name.from_text("0T7VH688AEK0612T69V8692OCMJD50M4.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "1HARMGSKJH0EBU2EI2OJIKTDPIQA6KBI" in str(rrset[0]).upper()
    # no WILDCARD (*.a.a.a.nsec3.example/8113LDMSEFPUAG4VGFF1C8KLOUT4Q6PH)
    rrset = res.get_rrset(
        res.authority,
        name.from_text("7AT0S0RIDCJRFF2M5H5AAV22CSFJBUL4.nsec3.example."),
        rdataclass.IN,
        rdatatype.NSEC3,
    )
    assert rrset, "expected NSEC3 missing from AUTHORITY: " + str(res)
    assert "BEJ5GMQA872JF4DAGQ0R3O5Q7A2O5S9L" in str(rrset[0]).upper()


def test_negative_validation_optout():
    # nxdomain
    msg = isctest.query.create("q.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # nodata
    msg = isctest.query.create("a.optout.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.empty_answer(res2)
    isctest.check.adflag(res2)

    # negative wildcard
    msg = isctest.query.create("b.wild.optout.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # empty NODATA
    msg = isctest.query.create("empty.optout.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # (rt22007 regression tests:)
    # check optout NSEC3 referral with only insecure delegatons
    msg = isctest.query.create("delegation.single-nsec3", "A")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.noerror(res)
    for rrset in res.authority:
        if (
            rrset.rdtype != rdatatype.NSEC3
            or "3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" not in rrset.name
        ):
            continue
        assert "1 1 1 - 3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" in str(rrset[0])

    # check optout NSEC3 NXDOMAIN with only insecure delegatons
    msg = isctest.query.create("nonexist.single-nsec3", "A")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.nxdomain(res)
    for rrset in res.authority:
        if (
            rrset.rdtype != rdatatype.NSEC3
            or "3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" not in rrset.name
        ):
            continue
        assert "1 1 1 - 3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" in str(rrset[0])

    # check optout NSEC3 NODATA with only insecure delegatons
    msg = isctest.query.create("single-nsec3", "A")
    res = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.noerror(res)
    for rrset in res.authority:
        if (
            rrset.rdtype != rdatatype.NSEC3
            or "3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" not in rrset.name
        ):
            continue
        assert "1 1 1 - 3KL3NK1HKQ4IUEEHBEF12VGFKUETNBAN" in str(rrset[0])

    # check negative unknown NSEC3-OPTOUT hash algorithm does not validate
    msg = isctest.query.create("optout-unknown.example", "A", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.servfail(res2)


def test_cache(ns4):
    # check that key id's are logged when dumping the cache
    ns4.rndc("dumpdb -cache", log=False)
    assert grep_q("; key id = ", "ns4/named_dump.db")

    # check for RRSIG covered type in negative cache
    assert grep_q("; example. RRSIG NSEC ", "ns4/named_dump.db")

    # check validated data are not cached longer than originalttl
    msg = isctest.query.create("a.ttlpatch.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.rr_count_eq(res1.answer, 2)
    isctest.check.rr_count_eq(res2.answer, 2)
    for rrset in res1.answer:
        assert 3000 <= rrset.ttl <= 3600
    for rrset in res2.answer:
        assert rrset.ttl <= 300

    # query for a record, then follow it with a query for the
    # corresponding RRSIG, check that it's answered from the cache
    msg = isctest.query.create("normalthenrrsig.secure.example", "A")
    isctest.query.tcp(msg, "10.53.0.4")

    msg = isctest.query.create("normalthenrrsig.secure.example", "RRSIG")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.raflag(res2)

    # check direct query for RRSIG: if it's not cached with other records,
    # it should result in an empty response.
    msg = isctest.query.create("rrsigonly.secure.example", "RRSIG")
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.empty_answer(res1)
    isctest.check.noraflag(res1)

    # check that a DNSKEY query with no data still gets cached
    msg = isctest.query.create("insecure.example", "DNSKEY")
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    time.sleep(1)  # give the TTL time to change
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    if res1.authority[0].ttl == res2.authority[0].ttl:
        time.sleep(1)
        res2 = isctest.query.tcp(msg, "10.53.0.4")
        assert res1.authority[0].ttl != res2.authority[0].ttl


def test_insecure_proof_nsec(ns4):
    # 1-server positive
    msg = isctest.query.create("a.insecure.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # 1-server negative
    msg = isctest.query.create("q.insecure.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # 1-server negative with SOA hack
    msg = isctest.query.create("r.insecure.example", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)
    assert res2.authority[0].rdtype == rdatatype.SOA
    assert res2.authority[0].ttl == 0

    # 2-server positive
    msg = isctest.query.create("a.insecure.secure.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # 2-server negative
    msg = isctest.query.create("q.insecure.secure.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # 2-server negative with SOA hack
    msg = isctest.query.create("r.insecure.secure.example", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # insecurity proof using negative cache
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("insecure.example", "DS", cd=True)
    isctest.query.tcp(msg, "10.53.0.4")

    def query_and_check_nxdomain():
        msg = isctest.query.create("nonexistent.insecure.example", "A")
        res = isctest.query.tcp(msg, "10.53.0.4")
        isctest.check.nxdomain(res)
        return True

    isctest.run.retry_with_timeout(query_and_check_nxdomain, 20)

    # check insecure negative response with an unsigned NSEC
    # first try the auth server...
    msg = isctest.query.create("nsec-rrsigs-stripped", "TXT")
    res1 = isctest.query.udp(msg, "10.53.0.10")
    isctest.check.noerror(res1)
    isctest.check.empty_answer(res1)
    isctest.check.rr_count_eq(res1.authority, 2)
    isctest.check.rr_count_eq(res1.additional, 0)
    # make sure there's no RRSIG(NSEC)
    for rrset in res1.authority:
        assert rrset.rdtype != rdatatype.RRSIG or rrset.covers != rdatatype.NSEC
    # now try the resolver
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noadflag(res2)


def test_insecure_proof_nsec3():
    # 1-server
    msg = isctest.query.create("a.insecure.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # 1-server negative
    msg = isctest.query.create("q.insecure.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # 1-server negative with SOA hack
    msg = isctest.query.create("r.insecure.nsec3.example", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)
    assert res2.authority[0].rdtype == rdatatype.SOA
    assert res2.authority[0].ttl == 0


def test_insecure_proof_optout():
    # 1-server
    msg = isctest.query.create("a.insecure.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # 1-server negative
    msg = isctest.query.create("q.insecure.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)

    # 1-server negative with SOA hack
    msg = isctest.query.create("r.insecure.optout.example", "SOA")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.noadflag(res2)
    assert res2.authority[0].rdtype == rdatatype.SOA
    assert res2.authority[0].ttl == 0


def test_below_cname():
    # check insecure zone below a cname resolves
    msg = isctest.query.create("insecure.below-cname.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.answer, 1)

    # check secure zone below a cname resolves and validates
    msg = isctest.query.create("secure.below-cname.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.answer, 2)


@pytest.mark.parametrize(
    "qname",
    [
        "a.secure.example",  # NSEC/NSEC
        "a.nsec3.example",  # NSEC/NSEC3
        "a.optout.example",  # NSEC/OPTOUT
        "a.secure.nsec3.example",  # NSEC3/NSEC
        "a.nsec3.nsec3.example",  # NSEC3/NSEC3
        "a.optout.nsec3.example",  # NSEC3/OPTOUT
        "a.secure.optout.example",  # OPTOUT/NSEC
        "a.nsec3.optout.example",  # OPTOUT/NSEC3
        "a.optout.optout.example",  # OPTOUT/OPTOUT
    ],
)
def test_positive_validation_multistage(qname):
    msg = isctest.query.create(qname, "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)


def test_validation_recovery(ns2, ns4):
    # check recovery from spoofed server address.
    # prime cache with spoofed address records...
    msg = isctest.query.create("target.peer-ns-spoof", "A", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)
    ns4.rndc("dumpdb", log=False)
    grep_q("10.53.0.100", "ns4/named_dump.db")

    # then reload server with properly signed zone
    shutil.copyfile(
        "ns2/peer.peer-ns-spoof.db.next", "ns2/peer.peer-ns-spoof.db.signed"
    )
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("reload peer.peer-ns-spoof", log=False)
        watcher.wait_for_line("zone peer.peer-ns-spoof/IN: loaded serial 2000042408")

    # and check we can resolve with the correct server address
    msg = isctest.query.create("test.target.peer-ns-spoof", "TXT")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)

    # check recovery from stripped DNSKEY RRSIG.
    # prime cache with spoofed address records...
    msg = isctest.query.create("dnskey-rrsigs-stripped", "DNSKEY", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 2)

    # then reload server with properly signed zone
    shutil.copyfile(
        "ns2/dnskey-rrsigs-stripped.db.next", "ns2/dnskey-rrsigs-stripped.db.signed"
    )
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("reload dnskey-rrsigs-stripped", log=False)
        watcher.wait_for_line(
            "zone dnskey-rrsigs-stripped/IN: loaded serial 2000042408"
        )

    # and check we can now resolve with the correct server address
    msg = isctest.query.create("b.dnskey-rrsigs-stripped", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # check recovery from stripped DS RRSIG.
    # prime cache with spoofed address records...
    msg = isctest.query.create("child.ds-rrsigs-stripped", "DS", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 1)

    # then reload server with properly signed zone
    shutil.copyfile(
        "ns2/ds-rrsigs-stripped.db.next", "ns2/ds-rrsigs-stripped.db.signed"
    )
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("reload ds-rrsigs-stripped", log=False)
        watcher.wait_for_line("zone ds-rrsigs-stripped/IN: loaded serial 2000042408")

    # and check we can now resolve with the correct server address
    msg = isctest.query.create("b.child.ds-rrsigs-stripped", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)

    # check recovery with mismatching NS
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("inconsistent", "NS", dnssec=False, cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.additional, 1)

    msg = isctest.query.create("inconsistent", "NS", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.additional, 1)

    msg = isctest.query.create("inconsistent", "NS")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.answer, 3)
    isctest.check.rr_count_eq(res.additional, 0)


def test_failed_validation():
    # bogus zone
    msg = isctest.query.create("a.bogus.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)

    # missing key record
    msg = isctest.query.create("a.b.keyless.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)


def test_revoked_key():
    # validation should succeed if a revoked key is encountered
    msg = isctest.query.create("revkey.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)


def test_standby_key():
    # check that a secure chain with one active and one inactive KSK
    # validates as secure
    msg = isctest.query.create("a.lazy-ksk", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)


def test_transitions():
    # check that a zone finishing transitioning from one algorithm
    # to another validates secure
    msg = isctest.query.create("algroll", "NS")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # check that validation yields insecure during transition to signed
    msg = isctest.query.create("inprogress", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    a, _ = res.answer
    assert str(a[0]) == "10.53.0.10"


def test_validating_forwarder(ns4, ns9):
    # check validating forwarder behavior with mismatching NS
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("inconsistent", "NS", dnssec=False, cd=True)
    res = isctest.query.tcp(msg, "10.53.0.9")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.additional, 0)
    isctest.check.noadflag(res)

    msg = isctest.query.create("inconsistent", "NS", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.9")
    isctest.check.rr_count_eq(res.additional, 0)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.authority, 0)
    isctest.check.rr_count_eq(res.additional, 0)

    msg.flags &= ~flags.CD
    res = isctest.query.tcp(msg, "10.53.0.9")
    isctest.check.rr_count_eq(res.answer, 3)
    isctest.check.rr_count_eq(res.authority, 0)
    isctest.check.rr_count_eq(res.additional, 0)
    isctest.check.adflag(res)

    # check validating forwarder sends CD to validate with a local trust anchor
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("localkey.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)

    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, "10.53.0.9")
        isctest.check.noerror(res)
        isctest.check.adflag(res)
        watcher.wait_for_line("status: SERVFAIL")


def test_expired_signatures(ns4):
    # check expired signatures do not validate
    msg = isctest.query.create("expired.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.3")
    rrsig = res.get_rrset(
        res.answer,
        name.from_text("expired.example."),
        rdataclass.IN,
        rdatatype.RRSIG,
        rdatatype.SOA,
    )
    assert rrsig, "expected RRSIG(SOA) missing from AUTHORITY: " + str(rrsig)
    isctest.check.rr_count_eq(res.answer, 2)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)
    isctest.check.noadflag(res)
    if hasattr(res, "extended_errors"):
        assert res.extended_errors()[0].code == edns.EDECode.SIGNATURE_EXPIRED
    assert grep_q("expired.example/.*: RRSIG has expired", "ns4/named.run")

    # check future signatures do not validate
    msg = isctest.query.create("future.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.servfail(res)
    isctest.check.noadflag(res)
    if hasattr(res, "extended_errors"):
        assert res.extended_errors()[0].code == edns.EDECode.SIGNATURE_NOT_YET_VALID
    assert grep_q(
        "future.example/.*: RRSIG validity period has not begun", "ns4/named.run"
    )

    # check that a dynamic zone with future signatures is re-signed on load
    msg = isctest.query.create("managed-future.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.adflag(res)
    isctest.check.noerror(res)

    # test TTL is capped at RRSIG expiry time
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expiring.example", "SOA", cd=True)
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expiring.example", "SOA")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.answer:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.answer:
        assert rrset.ttl <= 60

    # test TTL is capped at RRSIG expiry time in the additional section (NS)
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expiring.example", "NS", cd=True)
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expiring.example", "NS")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.additional:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.additional:
        assert rrset.ttl <= 60

    # test TTL is capped at RRSIG expiry time in the additional section (MX)
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("expiring.example", "MX", cd=True)
    res1 = isctest.query.tcp(msg, "10.53.0.4")
    msg = isctest.query.create("expiring.example", "MX")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    for rrset in res1.additional:
        assert 240 <= rrset.ttl <= 300
    for rrset in res2.additional:
        assert rrset.ttl <= 60


def test_casing():
    # test legacy upper-case signer name validation
    msg = isctest.query.create("upper.example", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.adflag(res)
    _, sig = res.answer
    assert sig.rdtype == rdatatype.RRSIG
    assert sig.covers == rdatatype.SOA
    assert "UPPER.EXAMPLE." in str(sig[0])

    # test that we lower-case signer name
    msg = isctest.query.create("LOWER.EXAMPLE", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.4")
    _, sig = res.answer
    assert sig.rdtype == rdatatype.RRSIG
    assert sig.covers == rdatatype.SOA
    assert "lower.example." in str(sig[0])


def test_broken_servers():
    # check that a non-cacheable NODATA works
    msg = isctest.query.create("a.nosoa.secure.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.6")
    isctest.check.rr_count_eq(res1.authority, 0)
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res2)

    # check that a non-cacheable NXDOMAIN works
    msg = isctest.query.create("b.nosoa.secure.example", "TXT")
    res1 = isctest.query.tcp(msg, "10.53.0.6")
    isctest.check.rr_count_eq(res1.authority, 0)
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.nxdomain(res2)

    # check that split RRSIGs are handled
    msg = isctest.query.create("split-rrsig", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.6")
    soa, _ = res.answer
    assert soa[0].serial > 1

    # check that not-at-zone-apex RRSIG(SOA) rrsets are removed
    msg = isctest.query.create("split-rrsig", "AXFR")
    res = isctest.query.tcp(msg, "10.53.0.6")

    nza = [
        r
        for r in res.answer
        if str(r.name) == "not-at-zone-apex.split-rrsig."
        and r.rdtype == rdatatype.RRSIG
        and r.covers == rdatatype.SOA
    ]
    assert not nza

    # check validation with missing nearest encloser proof
    msg = isctest.query.create("b.c.d.optout-tld", "DS")
    res = isctest.query.tcp(msg, "10.53.0.6")
    nsec3s = [a for a in res.authority if a.rdtype == rdatatype.NSEC3]
    assert len(nsec3s) == 2

    msg = isctest.query.create("b.c.d.optout-tld", "A")
    res = isctest.query.tcp(msg, "10.53.0.6")
    nsec3s = [a for a in res.authority if a.rdtype == rdatatype.NSEC3]
    assert len(nsec3s) == 1

    res = isctest.query.tcp(msg, "10.53.0.6")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    msg = isctest.query.create("optout-tld", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.6")
    isctest.check.noadflag(res)


def test_pending_ds(ns4):
    # check that a query against a validating resolver succeeds when there is
    # a negative cache entry with trust level "pending" for the DS.  prime
    # with a +cd DS query to produce the negative cache entry, then send a
    # query that uses that entry as part of the validation process.
    ns4.rndc("flush", log=False)
    msg = isctest.query.create("insecure.example", "DS", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 4)
    msg = isctest.query.create("a.insecure.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 1)
    isctest.check.rr_count_eq(res.authority, 1)
    isctest.check.noadflag(res)


def test_unknown_algorithms():
    # check that unknown DNSKEY algorithm validates as insecure
    msg = isctest.query.create("dnskey-unknown.example", "A", dnssec=False)
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # check that unsupported DNSKEY algorithms are in the DNSKEY RRsets
    msg = isctest.query.create("dnskey-unsupported.example", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    msg = isctest.query.create("dnskey-unsupported-2.example", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.noerror(res)
    rrsets = [str(r) for r in res.answer]
    assert any("257 3 255" in r for r in rrsets)

    # check that unsupported DNSKEY algorithm validates as insecure
    msg = isctest.query.create("dnskey-unsupported.example", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    if hasattr(res, "extended_errors"):
        assert (
            res.extended_errors()[0].code == edns.EDECode.UNSUPPORTED_DNSKEY_ALGORITHM
        )

    # check that DNSKEY with an unsupported reserve key validates
    msg = isctest.query.create("dnskey-unsupported-2.example", "DNSKEY")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # check EDE code 2 for unsupported DS digest algorithm
    msg = isctest.query.create("a.ds-unsupported.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    if hasattr(res, "extended_errors"):
        assert res.extended_errors()[0].code == edns.EDECode.UNSUPPORTED_DS_DIGEST_TYPE

    # check EDE code 1 for bad algorithm mnemonic
    msg = isctest.query.create("badalg.secure.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res)
    if hasattr(res, "extended_errors"):
        assert (
            res.extended_errors()[0].code == edns.EDECode.UNSUPPORTED_DNSKEY_ALGORITHM
        )

    # check both EDE code 1 and 2 for unsupported digest on one DNSKEY
    # and unsupported algorithm on the other
    msg = isctest.query.create("a.digest-alg-unsupported.example", "A")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res)
    if hasattr(res, "extended_errors"):
        codes = {ede.code for ede in res.extended_errors()}
        assert edns.EDECode.UNSUPPORTED_DNSKEY_ALGORITHM in codes
        assert edns.EDECode.UNSUPPORTED_DS_DIGEST_TYPE in codes

    # check that unknown DNSKEY algorithm + unknown NSEC3 hash algorithm
    # validates as insecure
    msg = isctest.query.create("dnskey-nsec3-unknown.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)
