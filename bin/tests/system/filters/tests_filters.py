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

import dns
from dns import message, rdataclass, rdatatype

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


# these are the default configuration values for the jinja2
# templates. if some other value is needed for a test, then
# the named.conf files must be regenerated.
filter_family = "v4"
filter_type = "aaaa"


def reset_servers(family, ftype, servers, templates):
    reset_server("ns1", family, ftype, servers, templates)
    reset_server("ns2", family, ftype, servers, templates)
    reset_server("ns3", family, ftype, servers, templates)
    reset_server("ns4", family, ftype, servers, templates)


def check_filtertype_only(dest, source, qname, ftype, expected, adflag):
    qname = dns.name.from_text(qname)
    msg = isctest.query.create(qname, ftype)
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    if adflag:
        isctest.check.adflag(res)
    else:
        isctest.check.noadflag(res)
    a_record = res.get_rrset(res.answer, qname, rdataclass.IN, rdatatype.A)
    aaaa_record = res.get_rrset(res.answer, qname, rdataclass.IN, rdatatype.AAAA)
    if ftype == "aaaa":
        assert not a_record
        if expected:
            assert (
                aaaa_record[0].address == expected
            ), f"expected AAAA {expected} in ANSWER: {res}"
    else:
        assert not aaaa_record
        if expected:
            assert (
                a_record[0].address == expected
            ), f"expected A {expected} in ANSWER: {res}"


def check_any(dest, source, qname, expected4, expected6, do):
    qname = dns.name.from_text(qname)
    msg = isctest.query.create(qname, "any", dnssec=do)
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    a_record = res.get_rrset(res.answer, qname, rdataclass.IN, rdatatype.A)
    if expected4:
        assert (
            a_record and a_record[0].address == expected4
        ), f"expected A {expected4} in ANSWER: {res}"
    else:
        assert not a_record
    aaaa_record = res.get_rrset(res.answer, qname, rdataclass.IN, rdatatype.AAAA)
    if expected6:
        assert (
            aaaa_record and aaaa_record[0].address == expected6
        ), f"expected AAAA {expected6} in ANSWER: {res}"
    else:
        assert not aaaa_record


def check_nodata(dest, source, qname, qtype, do, adflag):
    msg = isctest.query.create(qname, qtype, dnssec=do)
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    if adflag:
        isctest.check.adflag(res)
    else:
        isctest.check.noadflag(res)


def check_additional(dest, source, qname, qtype, ftype, expected, adcount):
    msg = isctest.query.create(qname, qtype)
    res = isctest.query.tcp(msg, dest, source=source)
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.additional, adcount)
    t = rdatatype.A if ftype == "a" else rdatatype.AAAA
    if expected:
        assert [a for a in res.additional if a.rdtype == t]
    else:
        assert not [a for a in res.additional if a.rdtype == t]


# run the checkconf tests
def test_checkconf():
    for filename in glob.glob("conf/good*.conf"):
        isctest.run.cmd([os.environ["CHECKCONF"], filename])
    for filename in glob.glob("conf/bad*.conf"):
        with pytest.raises(subprocess.CalledProcessError):
            isctest.run.cmd([os.environ["CHECKCONF"], filename])


def check_filter(addr, altaddr, ftype, break_dnssec, recursive):
    if recursive:
        # (when testing recursive, we need to prime the cache first with
        # the MX addresses, since additional section data isn't included
        # unless it's been validated.)
        for name in ["mx", "ns"]:
            for zone in ["signed", "unsigned"]:
                for qtype in ["a", "aaaa"]:
                    isctest.query.tcp(
                        isctest.query.create(f"{name}.{zone}", qtype), addr
                    )

    # check that AAAA is returned when only AAAA record exists, signed
    expected = "1.0.0.2" if ftype == "a" else "2001:db8::2"
    check_filtertype_only(
        addr, addr, f"{ftype}-only.signed", ftype, expected, recursive
    )

    # check that AAAA is returned when only AAAA record exists, unsigned
    expected = "1.0.0.5" if ftype == "a" else "2001:db8::5"
    check_filtertype_only(addr, addr, f"{ftype}-only.unsigned", ftype, expected, False)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # signed, DO=0
    check_nodata(addr, addr, "dual.signed", ftype, False, False)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=0
    check_nodata(addr, addr, "dual.unsigned", ftype, False, False)

    # check that AAAA is returned when both AAAA and A exist, signed,
    # DO=1, unless break-dnssec is enabled
    if break_dnssec:
        check_nodata(addr, addr, "dual.signed", ftype, False, False)
    else:
        expected = "1.0.0.3" if ftype == "a" else "2001:db8::3"
        check_filtertype_only(addr, addr, "dual.signed", ftype, expected, recursive)

    # check that NODATA/NOERROR is returned when both AAAA and A exist,
    # unsigned, DO=1
    check_nodata(addr, addr, "dual.unsigned", ftype, recursive, False)

    # check that AAAA is returned if both AAAA and A exist and the query
    # source doesn't match the ACL
    expected = "1.0.0.6" if ftype == "a" else "2001:db8::6"
    check_filtertype_only(addr, altaddr, "dual.unsigned", ftype, expected, False)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=0
    expected4 = "1.0.0.3" if ftype == "aaaa" else None
    expected6 = "2001:db8::3" if ftype == "a" else None
    check_any(addr, addr, "dual.signed", expected4, expected6, False)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, DO=1, unless break-dnssec is enabled
    if break_dnssec:
        if ftype == "a":
            expected4 = None
        else:
            expected6 = None
        check_any(addr, addr, "dual.signed", expected4, expected6, True)
    else:
        check_any(addr, addr, "dual.signed", "1.0.0.3", "2001:db8::3", True)

    expected4 = "1.0.0.6" if ftype == "aaaa" else None
    expected6 = "2001:db8::6" if ftype == "a" else None
    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=0
    check_any(addr, addr, "dual.unsigned", expected4, expected6, False)

    # check that A (and not AAAA) is returned if both AAAA and A exist,
    # unsigned, qtype=ANY, DO=1
    check_any(addr, addr, "dual.unsigned", expected4, expected6, True)

    # check that both A and AAAA are returned if both AAAA and A exist,
    # signed, qtype=ANY, query source does not match ACL
    check_any(addr, altaddr, "dual.unsigned", "1.0.0.6", "2001:db8::6", True)

    # check that AAAA is omitted from additional section, qtype=NS, unsigned
    check_additional(addr, addr, "unsigned", "ns", ftype, False, 1)

    # check that AAAA is omitted from additional section, qtype=MX, unsigned
    check_additional(addr, addr, "unsigned", "mx", ftype, False, 2)

    # check that AAAA is included in additional section, qtype=MX, signed,
    # unless break-dnssec is enabled
    if break_dnssec:
        check_additional(addr, addr, "signed", "mx", ftype, False, 4)
    else:
        check_additional(addr, addr, "signed", "mx", ftype, True, 8)


def check_filter_other_family(addr, ftype):
    # check that the filtered type is returned when both AAAA and A
    # record exists, unsigned, over IPv6
    check_filtertype_only(addr, addr, "dual.unsigned", ftype, None, False)

    # check that the filtered type is included in additional section,
    # qtype=MX, unsigned, over IPv6
    check_additional(addr, addr, "unsigned", "mx", ftype, True, 4)


def test_filter_aaaa_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    # ns1: auth, configured with:
    ## filter-aaaa-on-v4 yes;
    ## filter-aaaa { 10.53.0.1; };
    check_filter("10.53.0.1", "10.53.0.2", "aaaa", False, False)

    # ns4: auth, configured with:
    ## filter-aaaa-on-v4 break-dnssec;
    ## filter-aaaa { 10.53.0.4; };
    check_filter("10.53.0.4", "10.53.0.2", "aaaa", True, False)

    # ns2: recursive, configured with:
    ## filter-aaaa-on-v4 yes;
    ## filter-aaaa { 10.53.0.2; };
    check_filter("10.53.0.2", "10.53.0.1", "aaaa", False, True)

    # ns3: recursive, configured with:
    ## filter-aaaa-on-v4 break-dnssec;
    ## filter-aaaa { 10.53.0.3; };
    check_filter("10.53.0.3", "10.53.0.1", "aaaa", True, True)


@isctest.mark.with_ipv6
def test_filter_aaaa_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "aaaa":
        reset_servers("v4", "aaaa", servers, templates)

    check_filter_other_family("fd92:7065:b8e:ffff::1", "aaaa")
    check_filter_other_family("fd92:7065:b8e:ffff::2", "aaaa")
    check_filter_other_family("fd92:7065:b8e:ffff::3", "aaaa")
    check_filter_other_family("fd92:7065:b8e:ffff::4", "aaaa")


# These tests are against an authoritative server configured with:
## filter-aaaa-on-v6 yes;
@isctest.mark.with_ipv6
def test_filter_aaaa_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    # ns1: auth, configured with:
    ## filter-aaaa-on-v6 yes;
    ## filter-aaaa { fd92:7065:b8e:ffff::1; };
    check_filter("fd92:7065:b8e:ffff::1", "fd92:7065:b8e:ffff::2", "aaaa", False, False)

    # ns4: auth, configured with:
    ## filter-aaaa-on-v6 break-dnssec;
    ## filter-aaaa { fd92:7065:b8e:ffff::4; };
    check_filter("fd92:7065:b8e:ffff::4", "fd92:7065:b8e:ffff::2", "aaaa", True, False)

    # ns2: recursive, configured with:
    ## filter-aaaa-on-v6 yes;
    ## filter-aaaa { fd92:7065:b8e:ffff::2; };
    check_filter("fd92:7065:b8e:ffff::2", "fd92:7065:b8e:ffff::1", "aaaa", False, True)

    # ns3: recursive, configured with:
    ## filter-aaaa-on-v6 break-dnssec;
    ## filter-aaaa { fd92:7065:b8e:ffff::3; };
    check_filter("fd92:7065:b8e:ffff::3", "fd92:7065:b8e:ffff::1", "aaaa", True, True)


def test_filter_aaaa_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "aaaa":
        reset_servers("v6", "aaaa", servers, templates)

    check_filter_other_family("10.53.0.1", "aaaa")
    check_filter_other_family("10.53.0.2", "aaaa")
    check_filter_other_family("10.53.0.3", "aaaa")
    check_filter_other_family("10.53.0.4", "aaaa")


def test_filter_a_on_v4(servers, templates):
    if filter_family != "v4" or filter_type != "a":
        reset_servers("v4", "a", servers, templates)

    # ns1: auth, configured with:
    ## filter-a-on-v4 yes;
    ## filter-a { 10.53.0.1; };
    check_filter("10.53.0.1", "10.53.0.2", "a", False, False)

    # ns4: auth, configured with:
    ## filter-a-on-v4 break-dnssec;
    ## filter-a { 10.53.0.4; };
    check_filter("10.53.0.4", "10.53.0.2", "a", True, False)

    # ns2: recursive, configured with:
    ## filter-a-on-v4 yes;
    ## filter-a { 10.53.0.2; };
    check_filter("10.53.0.2", "10.53.0.1", "a", False, True)

    # ns3: recursive, configured with:
    ## filter-a-on-v4 break-dnssec;
    ## filter-a { 10.53.0.3; };
    check_filter("10.53.0.3", "10.53.0.1", "a", True, True)


@isctest.mark.with_ipv6
def test_filter_a_on_v4_via_v6(servers, templates):
    if filter_family != "v4" or filter_type != "a":
        reset_servers("v4", "a", servers, templates)

    check_filter_other_family("fd92:7065:b8e:ffff::1", "a")
    check_filter_other_family("fd92:7065:b8e:ffff::2", "a")
    check_filter_other_family("fd92:7065:b8e:ffff::3", "a")
    check_filter_other_family("fd92:7065:b8e:ffff::4", "a")


# These tests are against an authoritative server configured with:
## filter-a-on-v6 yes;
@isctest.mark.with_ipv6
def test_filter_a_on_v6(servers, templates):
    if filter_family != "v6" or filter_type != "a":
        reset_servers("v6", "a", servers, templates)

    # ns1: auth, configured with:
    ## filter-a-on-v6 yes;
    ## filter-a { fd92:7065:b8e:ffff::1; };
    check_filter("fd92:7065:b8e:ffff::1", "fd92:7065:b8e:ffff::2", "a", False, False)

    # ns4: auth, configured with:
    ## filter-a-on-v6 break-dnssec;
    ## filter-a { fd92:7065:b8e:ffff::4; };
    check_filter("fd92:7065:b8e:ffff::4", "fd92:7065:b8e:ffff::2", "a", True, False)

    # ns2: recursive, configured with:
    ## filter-a-on-v6 yes;
    ## filter-a { fd92:7065:b8e:ffff::2; };
    check_filter("fd92:7065:b8e:ffff::2", "fd92:7065:b8e:ffff::1", "a", False, True)

    # ns3: recursive, configured with:
    ## filter-a-on-v6 break-dnssec;
    ## filter-a { fd92:7065:b8e:ffff::3; };
    check_filter("fd92:7065:b8e:ffff::3", "fd92:7065:b8e:ffff::1", "a", True, True)


def test_filter_a_on_v6_via_v4(servers, templates):
    if filter_family != "v6" or filter_type != "a":
        reset_servers("v6", "a", servers, templates)

    check_filter_other_family("10.53.0.1", "a")
    check_filter_other_family("10.53.0.2", "a")
    check_filter_other_family("10.53.0.3", "a")
    check_filter_other_family("10.53.0.4", "a")
