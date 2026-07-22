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

"""
Tests for the dig tool.
"""

from re import compile as Re

import os
import re

import pytest

from digdelv.common import ARTIFACTS, check_ttl_range
from isctest.util import param

import isctest

pytestmark = [
    pytest.mark.skipif(
        not os.access(os.environ.get("DIG", ""), os.X_OK),
        reason="dig executable not available",
    ),
    pytest.mark.extra_artifacts(ARTIFACTS),
]


@pytest.fixture(name="dig")
def dig_fixture(named_port):
    return isctest.run.EnvCmd("DIG", f"-p {named_port}")


def test_update_response(dig, ans6):
    """Check that dig rejects a response with the UPDATE opcode."""
    result = dig(
        f"@{ans6.ip} +tries=1 +timeout=1 cname foo.bar", raise_on_exception=False
    )
    assert result.rc != 0
    assert "Opcode mismatch" in result.out


def test_short(dig, ns3):
    """Check that dig +short returns a single-line answer."""
    result = dig(f"@{ns3.ip} +short a a.example")
    assert len(result.out.splitlines()) == 1


@pytest.mark.parametrize("option", ["+split=4", "+sp=4"])
def test_split_width(dig, ns3, option):
    """Check that dig +split (and its +sp abbreviation) splits hex data
    into fields of the requested width."""
    result = dig(f"@{ns3.ip} {option} -t sshfp foo.example")
    assert " 9ABC DEF6 7890 " in result.out
    assert check_ttl_range(result.out, "SSHFP", 300)


def test_unknownformat(dig, ns3):
    """Check that dig +unknownformat prints RFC 3597 format."""
    result = dig(f"@{ns3.ip} +unknownformat a a.example")
    assert Re(r"CLASS1\s+TYPE1\s+\\# 4 0A000001") in result.out
    assert check_ttl_range(result.out, "TYPE1", 300)


def test_reverse_lookup(dig, ns3):
    """Check that dig -x works."""
    result = dig(f"@{ns3.ip} -x 127.0.0.1")
    # doesn't matter if has answer
    assert Re(r"127\.in-addr\.arpa\.", re.IGNORECASE) in result.out
    assert check_ttl_range(result.out, "SOA", 86400)


def test_tcp(dig, ns3):
    """Check that dig over TCP works."""
    result = dig(f"+tcp @{ns3.ip} a a.example")
    assert Re(r"10\.0\.0\.1$") in result.out
    assert check_ttl_range(result.out, "A", 300)


@pytest.mark.parametrize(
    "args,expect_rrcomment",
    [
        param("+multi +norrcomments -t DNSKEY example", False, id="multi-norrcomments"),
        param("+rrcomments DNSKEY example", True, id="rrcomments"),
        param("+short +rrcomments DNSKEY example", True, id="short-rrcomments"),
    ],
)
def test_dnskey_rrcomments(dig, ns3, zsk, args, expect_rrcomment):
    """Check that +[no]rrcomments controls the DNSKEY comment
    (the default is rrcomments, even with +multi)."""
    result = dig(f"+tcp @{ns3.ip} {args}")
    assert (zsk.rrcomment in result.out) == expect_rrcomment
    if "+short" not in args:
        assert check_ttl_range(result.out, "DNSKEY", 300)


def test_soa_norrcomments(dig, ns3):
    """Check that +multi +norrcomments suppresses the SOA field comments."""
    result = dig(f"+tcp @{ns3.ip} +multi +norrcomments -t SOA example")
    assert "; serial" not in result.out
    assert check_ttl_range(result.out, "SOA", 300)


def test_short_nosplit(dig, ns3, zsk):
    """Check that dig +short +nosplit does not split the key data."""
    result = dig(f"+tcp @{ns3.ip} +short +nosplit DNSKEY example")
    assert zsk.keydata.replace(" ", "") in result.out


def test_short_rrcomments_line(dig, ns3, zsk):
    """Check the exact dig +short +rrcomments output line."""
    result = dig(f"+tcp @{ns3.ip} +short +rrcomments DNSKEY example")
    expected = re.escape(f"{zsk.keydata}  {zsk.rrcomment}")
    assert Re(expected + "$") in result.out


def test_multi_flag_is_local(dig, ns3):
    """Check that +[no]multi applies to a single lookup only."""
    lines = {}
    for flags in [
        ("nomulti", "nomulti"),
        ("multi", "nomulti"),
        ("nomulti", "multi"),
        ("multi", "multi"),
    ]:
        first, second = flags
        result = dig(f"+tcp @{ns3.ip} -t DNSKEY example +{first} example +{second}")
        assert check_ttl_range(result.out, "DNSKEY", 300)
        lines[flags] = len(result.out.splitlines())
    assert lines[("multi", "multi")] >= lines[("nomulti", "multi")]
    assert lines[("multi", "multi")] >= lines[("multi", "nomulti")]
    assert lines[("nomulti", "multi")] >= lines[("nomulti", "nomulti")]
    assert lines[("multi", "nomulti")] >= lines[("nomulti", "nomulti")]


def test_noheader_only(dig, ns3):
    """Check that dig +noheader-only sends a full query."""
    result = dig(f"+tcp @{ns3.ip} +noheader-only A example")
    assert "Got answer:" in result.out
    assert check_ttl_range(result.out, "SOA", 300)


@pytest.mark.parametrize(
    "class_type",
    [
        param("", id="default"),
        param("-c IN -t A", id="with-class-and-type"),
    ],
)
def test_header_only(dig, ns3, class_type):
    """Check that dig +header-only sends a query without a question."""
    result = dig(f"+tcp @{ns3.ip} +header-only {class_type} example")
    assert Re(r"^;; flags: qr rd; QUERY: 0, ANSWER: 0,") in result.out
    assert Re(r"^;; QUESTION SECTION:") not in result.out


@pytest.mark.parametrize(
    "qname,ttl",
    [
        param("weeks", "3w"),
        param("days", "3d"),
        param("hours", "3h"),
        param("minutes", "45m"),
        param("seconds", "45s"),
    ],
)
def test_ttl_units(dig, ns2, qname, ttl):
    """Check that dig +ttlunits prints TTLs in time units."""
    result = dig(f"+tcp @{ns2.ip} +ttlunits A {qname}.example")
    assert Re(rf"^{qname}\.example\.\s+{ttl}\s") in result.out


@pytest.mark.parametrize(
    "options,field",
    [
        param("+ttlunits +nottlid", "IN", id="nottlid-wins"),
        param("+nottlid +ttlunits", "3w", id="ttlunits-wins"),
        param("+nottlid +nottlunits", "1814400", id="plain-seconds"),
    ],
)
def test_ttl_units_precedence(dig, ns2, options, field):
    """Check that the last of the +ttlid/+ttlunits options wins."""
    result = dig(f"+tcp @{ns2.ip} {options} A weeks.example")
    assert Re(rf"^weeks\.example\.\s+{re.escape(field)}\s") in result.out


def test_class_chaos(dig, ns3):
    """Check that dig -c CHAOS works."""
    result = dig(f"@{ns3.ip} -c CHAOS -t txt version.bind")
    assert "version.bind.\t\t0\tCH\tTXT" in result.out


def test_bad_escape(dig, ns3):
    """Check that dig gracefully rejects a bad escape in the domain name."""
    result = dig(rf"@{ns3.ip} \0.", raise_on_exception=False)
    assert result.rc == 10
    assert "REQUIRE" not in result.err
    assert "is not a legal name (bad escape)" in result.err


def test_q_m(dig, ns3):
    """Check that -q -m treats -m as a query name, not as the memory
    debugging flag."""
    result = dig(f"@{ns3.ip} -q -m", raise_on_exception=False)
    assert Re(r"^;-m\..*IN.*A$") in result.out
    assert "Dump of all outstanding memory allocations" not in result.out


@pytest.mark.parametrize(
    "options,pattern",
    [
        param(
            "+expandaaaa",
            r"ns2\.example.*fd92:7065:0b8e:ffff:0000:0000:0000:0002",
            id="expandaaaa",
        ),
        param(
            "+noexpandaaaa", r"ns2\.example.*fd92:7065:b8e:ffff::2", id="noexpandaaaa"
        ),
        param("", r"ns2\.example.*fd92:7065:b8e:ffff::2", id="default"),
        param(
            "+short +expandaaaa",
            r"^fd92:7065:0b8e:ffff:0000:0000:0000:0002$",
            id="short-expandaaaa",
        ),
    ],
)
def test_expandaaaa(dig, ns3, options, pattern):
    """Check that +[no]expandaaaa controls AAAA address formatting
    (the default is +noexpandaaaa)."""
    result = dig(f"@{ns3.ip} {options} AAAA ns2.example")
    assert Re(pattern) in result.out


def test_bufsize_zero(dig, ns3):
    """Check that +bufsize=0 just sets the advertised buffer size to 0
    instead of disabling EDNS."""
    result = dig(f"@{ns3.ip} a.example +bufsize=0 +qr")
    assert "EDNS:" in result.out


def test_bufsize_restores_default(dig, ns3):
    """Check that a later +bufsize restores the default buffer size."""
    result = dig(f"@{ns3.ip} a.example +bufsize=0 +bufsize +qr")
    assert len(result.out.grep(Re(r"EDNS:.* udp:"))) == 2
    assert len(result.out.grep(Re(r"EDNS:.* udp: 1232"))) == 2


@pytest.mark.parametrize(
    "options,unit",
    [
        param("", "msec", id="msec"),
        param("-u", "usec", id="usec"),
    ],
)
def test_query_time_units(dig, ns3, options, unit):
    """Check that Query time is in milliseconds, or in microseconds
    with -u."""
    result = dig(f"{options} @{ns3.ip} a.example")
    assert Re(rf";; Query time: \d+ {unit}") in result.out


@pytest.mark.parametrize(
    "options,digits",
    [
        param("+yaml", 3, id="msec"),
        param("-u +yaml", 6, id="usec"),
    ],
)
def test_yaml_timestamp_precision(dig, ns3, options, digits):
    """Check that +yaml timestamps have millisecond precision, or
    microsecond precision with -u."""
    result = dig(f"{options} @{ns3.ip} a.example")
    for field in ("query_time", "response_time"):
        pattern = (
            rf"{field}: !!timestamp \d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{{{digits}}}Z"
        )
        assert Re(pattern) in result.out


def test_local_reserved_warning(dig, ns3):
    """Check that dig warns about .local queries."""
    result = dig(f"@{ns3.ip} local soa")
    assert ";; WARNING: .local is reserved for Multicast DNS" in result.out


def test_nocrypto(dig, ns1):
    """Check that +nocrypto omits the key and signature data."""
    alg_num = os.environ["DEFAULT_ALGORITHM_NUMBER"]
    result = dig(f"+dnssec +norec +nocrypto DNSKEY . @{ns1.ip}")
    assert Re(rf"256 \d+ {alg_num} \[key id = [1-9]\d*]") in result.out
    assert Re(r"RRSIG.* \[omitted]") in result.out
    result = dig(f"+norec +nocrypto DS example @{ns1.ip}")
    assert Re(r"DS.* \d+ [12] \[omitted]") in result.out
