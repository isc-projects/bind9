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
    templates.render(f"{server}/named.conf", {"family": family, "filtertype": ftype})
    servers[server].reconfigure(log=False)


filter_family = "v4"
filter_type = "aaaa"


def reset_servers(family, ftype, servers, templates):
    reset_server("ns1", family, ftype, servers, templates)
    reset_server("ns2", family, ftype, servers, templates)
    reset_server("ns3", family, ftype, servers, templates)
    reset_server("ns4", family, ftype, servers, templates)
    filter_family = family


def check_aaaa_only(dest, source, qname, expected, adflag):
    msg = isctest.query.create(qname, "aaaa")
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    if adflag:
        isctest.check.adflag(res)
    else:
        isctest.check.noadflag(res)
    assert not [a for a in res.answer if a.rdtype == rdatatype.A]
    aaaa = res.answer[0]
    assert aaaa.rdtype == rdatatype.AAAA
    assert expected in str(aaaa[0])


def check_any(dest, source, qname, expected4, expected6, do):
    if do:
        msg = isctest.query.create(qname, "any")  # sends DO=1
    else:
        msg = message.make_query(qname, "any")  # sends DO=0
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    records = sum([str(a).splitlines() for a in res.answer], [])
    if expected4:
        assert any(expected4 in r for r in records), str(res)
    else:
        assert not any(a.rdtype == rdatatype.A for a in res.answer), str(res)
    if expected6:
        assert any(expected6 in r for r in records), str(res)
    else:
        assert not any(a.rdtype == rdatatype.AAAA for a in res.answer), str(res)


def check_nodata(dest, source, qname, qtype, do, adflag):
    if do:
        msg = isctest.query.create(qname, qtype)  # sends DO=1
    else:
        msg = message.make_query(qname, qtype)  # sends DO=0
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    if adflag:
        isctest.check.adflag(res)
    else:
        isctest.check.noadflag(res)


def check_additional(dest, source, qname, qtype, expect_aaaa, adcount):
    msg = isctest.query.create(qname, qtype)
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, adcount)
    if expect_aaaa:
        assert [a for a in res.additional if a.rdtype == rdatatype.AAAA]
    else:
        assert not [a for a in res.additional if a.rdtype == rdatatype.AAAA]


# run the checkconf tests
def test_checkconf():
    for filename in glob.glob("conf/good*.conf"):
        isctest.run.cmd([os.environ["CHECKCONF"], filename])
    for filename in glob.glob("conf/bad*.conf"):
        with pytest.raises(subprocess.CalledProcessError):
            isctest.run.cmd([os.environ["CHECKCONF"], filename])


def check_filter(addr, altaddr, break_dnssec, recursive):
    if recursive:
        # (when testing recursive, we need to prime the cache first with
        # the MX addresses, since additional section data isn't included
        # unless it's been validated.)
        for name in ["mx", "ns"]:
            for zone in ["signed", "unsigned"]:
                for qtype in ["a", "aaaa"]:
                    isctest.query.tcp(isctest.query.create(f"{name}.{zone}", qtype), addr)

    # check that AAAA is returned when only AAAA record exists, signed
    check_aaaa_only(addr, addr, "aaaa-only.signed", "2001:db8::2", recursive)

    # check that AAAA is returned when only AAAA record exists, unsigned
    check_aaaa_only(addr, addr, "aaaa-only.unsigned", "2001:db8::5", False)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0
    check_nodata(addr, addr, "dual.signed", "aaaa", False, False)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0
    check_nodata(addr, addr, "dual.unsigned", "aaaa", False, False)

    # check that AAAA is returned when both AAAA and A exist, signed,
    # DO=1, unless break-dnssec is enabled
    if break_dnssec:
        check_nodata(addr, addr, "dual.signed", "aaaa", False, False)
    else:
        check_aaaa_only(addr, addr, "dual.signed", "2001:db8::3", recursive)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1
    check_nodata(addr, addr, "dual.unsigned", "aaaa", recursive, False)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    check_aaaa_only(addr, altaddr, "dual.unsigned", "2001:db8::6", False)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0
    check_any(addr, addr, "dual.signed", "1.0.0.3", None, False)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, unless break-dnssec is enabled
    if break_dnssec:
        check_any(addr, addr, "dual.signed", "1.0.0.3", None, True)
    else:
        check_any(addr, addr, "dual.signed", "1.0.0.3", "2001:db8::3", True)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0
    check_any(addr, addr, "dual.unsigned", "1.0.0.6", None, False)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1
    check_any(addr, addr, "dual.unsigned", "1.0.0.6", None, True)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL
    check_any(addr, altaddr, "dual.unsigned", "1.0.0.6", "2001:db8::6", True)

    # check that AAAA is omitted from additional section, qtype=NS, unsigned
    check_additional(addr, addr, "unsigned", "ns", False, 1)

    # check that AAAA is omitted from additional section, qtype=MX, unsigned
    check_additional(addr, addr, "unsigned", "mx", False, 2)

    # check that AAAA is included in additional section, qtype=MX, signed,
    # unless break-dnssec is enabled
    if break_dnssec:
        check_additional(addr, addr, "signed", "mx", False, 4)
    else:
        check_additional(addr, addr, "signed", "mx", True, 8)


def check_filter_other_family(addr):
    # check that AAAA is returned when both AAAA and A record exists,
    # unsigned, over IPv6
    check_aaaa_only(addr, addr, "dual.unsigned", "2001:db8::6", False)

    # check that AAAA is included in additional section, qtype=MX,
    # unsigned, over IPv6
    check_additional(addr, addr, "unsigned", "mx", True, 4)


def test_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # ns1: auth, configured with:
    ## filter-aaaa-on-v4 yes;
    ## filter-aaaa { 10.53.0.1; };
    check_filter("10.53.0.1", "10.53.0.2", False, False)

    # ns4: auth, configured with:
    ## filter-aaaa-on-v4 break-dnssec;
    ## filter-aaaa { 10.53.0.4; };
    check_filter("10.53.0.4", "10.53.0.2", True, False)

    # ns2: recursive, configured with:
    ## filter-aaaa-on-v4 yes;
    ## filter-aaaa { 10.53.0.2; };
    check_filter("10.53.0.2", "10.53.0.1", False, True)

    # ns3: recursive, configured with:
    ## filter-aaaa-on-v4 break-dnssec;
    ## filter-aaaa { 10.53.0.3; };
    check_filter("10.53.0.3", "10.53.0.1", True, True)


@isctest.mark.with_ipv6
def test_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    check_filter_other_family("fd92:7065:b8e:ffff::1")
    check_filter_other_family("fd92:7065:b8e:ffff::2")
    check_filter_other_family("fd92:7065:b8e:ffff::3")
    check_filter_other_family("fd92:7065:b8e:ffff::4")


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v6 yes;
@isctest.mark.with_ipv6
def test_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # ns1: auth, configured with:
    ## filter-aaaa-on-v6 yes;
    ## filter-aaaa { fd92:7065:b8e:ffff::1; };
    check_filter("fd92:7065:b8e:ffff::1", "fd92:7065:b8e:ffff::2", False, False)

    # ns4: auth, configured with:
    ## filter-aaaa-on-v6 break-dnssec;
    ## filter-aaaa { fd92:7065:b8e:ffff::4; };
    check_filter("fd92:7065:b8e:ffff::4", "fd92:7065:b8e:ffff::2", True, False)

    # ns2: recursive, configured with:
    ## filter-aaaa-on-v6 yes;
    ## filter-aaaa { fd92:7065:b8e:ffff::2; };
    check_filter("fd92:7065:b8e:ffff::2", "fd92:7065:b8e:ffff::1", False, True)

    # ns3: recursive, configured with:
    ## filter-aaaa-on-v6 break-dnssec;
    ## filter-aaaa { fd92:7065:b8e:ffff::3; };
    check_filter("fd92:7065:b8e:ffff::3", "fd92:7065:b8e:ffff::1", True, True)


def test_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    check_filter_other_family("10.53.0.1")
    check_filter_other_family("10.53.0.2")
    check_filter_other_family("10.53.0.3")
    check_filter_other_family("10.53.0.4")
