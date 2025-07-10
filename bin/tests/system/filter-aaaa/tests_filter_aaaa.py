#!/bin/sh

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

import glob
import os
import subprocess

from dns import message, rdatatype

import pytest

import isctest
import isctest.mark


pytestmark = pytest.mark.extra_artifacts(
    [
        "conf/*.conf",
        "ns*/trusted.conf",
        "ns*/*.signed",
        "ns*/K*",
        "ns*/dsset-*",
        "ns*/signer.err",
    ]
)


# helper functions
def reset_server(server, family, ftype, servers, templates):
    templates.render(f"{server}/named.conf",
            {"family": family, "filtertype": ftype})
    servers[server].reconfigure(log=False)


filter_family = "v4"
filter_type = "aaaa"
def reset_servers(family, ftype, servers, templates):
    reset_server("ns1", family, ftype, servers, templates)
    reset_server("ns2", family, ftype, servers, templates)
    reset_server("ns3", family, ftype, servers, templates)
    reset_server("ns4", family, ftype, servers, templates)
    filter_family = family


# run the checkconf tests
def test_checkconf():
    for filename in glob.glob("conf/good*.conf"):
        isctest.run.cmd([os.environ["CHECKCONF"], filename])
    for filename in glob.glob("conf/bad*.conf"):
        with pytest.raises(subprocess.CalledProcessError):
            isctest.run.cmd([os.environ["CHECKCONF"], filename])


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v4 yes;
## filter-aaaa { 10.53.0.1; };
def test_auth_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa = res.answer[0]
    assert "2001:db8::3" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS, unsigned
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX, unsigned
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is included in additional section, qtype=MX, signed
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


@isctest.mark.with_ipv6
def test_auth_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v4 break-dnssec;
## filter-aaaa { 10.53.0.4; };
def test_auth_break_dnssec_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # with break-dnssec
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # with break-dnssec
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, with break-dnssec
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, with break-dnssec
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1,
    # with break-dnssec
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, with break-dnssec
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, with break-dnssec
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, with break-dnssec
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, with break-dnssec
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # signed, with break-dnssec
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "10.53.0.4", source="10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]


@isctest.mark.with_ipv6
def test_auth_break_dnssec_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against a recursive server configured with:
## filter-aaaa-on-v4 yes;
## filter-aaaa { 10.53.0.2; };
def test_recursive_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # recursive
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # recursive
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, recursive
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, recursive
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1,
    # recursive
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa = res.answer[0]
    assert "2001:db8::3" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noadflag(res)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, recursive
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, recursive
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, recursive
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, recursive
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, recursive
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # (we need to prime the cache first with the MX addresses, since
    # additional section data isn't included unless it's already validated.)
    msg = isctest.query.create("mx.signed", "a")
    isctest.query.tcp(msg, "10.53.0.2")
    msg = isctest.query.create("mx.signed", "aaaa")
    isctest.query.tcp(msg, "10.53.0.2")

    # check that AAAA is included in additional section, qtype=MX, signed,
    # recursive
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


@isctest.mark.with_ipv6
def test_recursive_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against a recursive server configured with:
## filter-aaaa-on-v4 break-dnssec;
## filter-aaaa { 10.53.0.3; };
def test_recursive_break_dnssec_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # recursive, with break-dnssec
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # recursive, with break-dnssec
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noadflag(res)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, recursive, with
    # break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, recursive, with break-dnssec
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, recursive, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX, signed,
    # recursive, with break-dnssec
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "10.53.0.3", source="10.53.0.3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]


@isctest.mark.with_ipv6
def test_recursive_break_dnssec_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v6 yes;
## filter-aaaa { fd92:7065:b8e:ffff::1; };
@isctest.mark.with_ipv6
def test_auth_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa = res.answer[0]
    assert "2001:db8::3" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS, unsigned
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX, unsigned
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is included in additional section, qtype=MX, signed
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::1",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


def test_auth_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v6 break-dnssec;
## filter-aaaa { fd92:7065:b8e:ffff::4; };
@isctest.mark.with_ipv6
def test_auth_break_dnssec_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # with break-dnssec
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # with break-dnssec
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, with break-dnssec
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, with break-dnssec
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1,
    # with break-dnssec
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, with break-dnssec
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, with break-dnssec
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, with break-dnssec
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, with break-dnssec
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # signed, with break-dnssec
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::4",
            source="fd92:7065:b8e:ffff::4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]


def test_auth_break_dnssec_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against a recursive server configured with:
## filter-aaaa-on-v6 yes;
## filter-aaaa { fd92:7065:b8e:ffff::2; };
@isctest.mark.with_ipv6
def test_recursive_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # recursive
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # recursive
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, recursive
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, recursive
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned when both AAAA and A exist, signed, DO=1,
    # recursive
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    isctest.check.rr_count_eq(res.authority, 2)
    aaaa = res.answer[0]
    assert "2001:db8::3" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noadflag(res)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, recursive
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, recursive
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, recursive
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, recursive
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, recursive
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # (we need to prime the cache first with the MX addresses, since
    # additional section data isn't included unless it's already validated.)
    msg = isctest.query.create("mx.signed", "a")
    isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2")
    msg = isctest.query.create("mx.signed", "aaaa")
    isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2")

    # check that AAAA is included in additional section, qtype=MX, signed,
    # recursive
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::2",
            source="fd92:7065:b8e:ffff::2")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


def test_recursive_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# These tests are against a recursive server configured with:
## filter-aaaa-on-v6 break-dnssec;
## filter-aaaa { fd92:7065:b8e:ffff::3; };
@isctest.mark.with_ipv6
def test_recursive_break_dnssec_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when only AAAA record exists, signed,
    # recursive, with break-dnssec
    msg = isctest.query.create("aaaa-only.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    aaaa, _ = res.answer
    assert "2001:db8::2" in str(aaaa[0])

    # check that AAAA is returned when only AAAA record exists, unsigned,
    # recursive, with break-dnssec
    msg = isctest.query.create("aaaa-only.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    aaaa = res.answer[0]
    assert "2001:db8::5" in str(aaaa[0])

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.signed", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.unsigned", "aaaa") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.signed", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.empty_answer(res)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noadflag(res)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.signed", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = isctest.query.create("dual.signed", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.3" in r for r in records)
    assert not any("2001:db8::3" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0, recursive, with break-dnssec
    msg = message.make_query("dual.unsigned", "any") # sends DO=0
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1, recursive, with break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert not any("2001:db8::6" in r for r in records)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL, recursive, with
    # break-dnssec
    msg = isctest.query.create("dual.unsigned", "any")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::1")
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert any("1.0.0.6" in r for r in records)
    assert any("2001:db8::6" in r for r in records)

    # check that AAAA is omitted from additional section, qtype=NS,
    # unsigned, recursive, with break-dnssec
    msg = isctest.query.create("unsigned", "ns")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 1)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX,
    # unsigned, recursive, with break-dnssec
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]

    # check that AAAA is omitted from additional section, qtype=MX, signed,
    # recursive, with break-dnssec
    msg = isctest.query.create("signed", "mx")
    res = isctest.query.tcp(msg, "fd92:7065:b8e:ffff::3",
            source="fd92:7065:b8e:ffff::3")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 2)
    assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]


def test_recursive_break_dnssec_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("dual.unsigned", "aaaa")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    aaaa = res.answer[0]
    assert "2001:db8::6" in str(aaaa[0])

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6, recursive
    msg = isctest.query.create("unsigned", "mx")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.authority, 1)
    assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]
