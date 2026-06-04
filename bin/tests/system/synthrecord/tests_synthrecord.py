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

# Silence incorrect warnings cause by hypothesis.assume()
# https://github.com/pylint-dev/pylint/issues/10785#issuecomment-3677224217
# pylint: disable=unreachable

from ipaddress import IPv4Address, IPv6Address

import glob
import os
import subprocess

from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain
from hypothesis import assume, example, given
from hypothesis.strategies import ip_addresses

import dns.message
import dns.name
import dns.rcode
import dns.rrset
import pytest

from isctest.hypothesis.strategies import dns_names

import isctest

SERVER = "10.53.0.1"

pytestmark = pytest.mark.extra_artifacts(
    [
        "conf/*.conf",
        "managed-keys.bind.jnl",
    ]
)


def test_synthrecord_checkconf():
    for filename in glob.glob("conf/good*.conf"):
        isctest.run.cmd([os.environ["CHECKCONF"], filename])
    for filename in glob.glob("conf/bad*.conf"):
        with pytest.raises(subprocess.CalledProcessError):
            isctest.run.cmd([os.environ["CHECKCONF"], filename])


@pytest.mark.parametrize(
    "qname, rname, ttl",
    [
        ("5.2.168.192.in-addr.arpa", "dynamic-192-168-2-5.example.", 3600),
        ("44.0.53.10.IN-ADDR.ARPA", "dynamic-10-53-0-44.example.", 3600),
        ("44.0.53.10.In-adDR.ArPA", "dynamic-10-53-0-44.example.", 3600),
        ("44.0.53.10.in-addr.arpa", "dynamic-10-53-0-44.example.", 3600),
        ("44.0.53.10.in-addr.arpa.", "dynamic-10-53-0-44.example.", 3600),
        ("4.0.53.10.in-addr.arpa", "a.example.", 120),
        ("4.0.53.10.in-addr.arpa.", "a.example.", 120),
        ("4.1.53.10.in-addr.arpa.", "dynamic-10-53-1-4.example.", 3600),
        ("28.0.53.10.in-addr.arpa", "b.example.", 120),
        ("28.0.53.10.in-addr.arpa.", "b.example.", 120),
        ("2.1.53.10.in-addr.arpa.", "dynamic-10-53-1-2.example.", 3600),
        (
            "e.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa",
            "dynamic-cafe-cafe--cafe.example.",
            3600,
        ),
        (
            "e.F.a.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.A.C.E.f.a.c.iP6.ArpA",
            "dynamic-cafe-cafe--cafe.example.",
            3600,
        ),
        (
            "e.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa.",
            "dynamic-cafe-cafe--cafe.example.",
            3600,
        ),
        (
            "e.f.a.c.f.e.e.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa.",
            "aaaa.example.",
            120,
        ),
    ],
)
def test_synthrecord_reverse_hasdata(qname, rname, ttl):
    msg = dns.message.make_query(qname, "PTR")
    res = isctest.query.udp(msg, SERVER)
    isctest.check.noerror(res)
    if qname[-1] != ".":
        qname += "."
    assert len(res.answer) == 1
    assert res.answer[0].ttl == ttl
    assert res.answer[0] == dns.rrset.from_text(qname, ttl, "IN", "PTR", rname)


@pytest.mark.parametrize(
    "qname, qtype, rname, rtype, ttl",
    [
        ("dynamic-10-53-0-44.example.", "A", "10.53.0.44", "A", 3600),
        ("dYnAmIc-10-53-0-44.example.", "A", "10.53.0.44", "A", 3600),
        ("dYnAmIc-10-53-0-44.example.", "ANY", "10.53.0.44", "A", 3600),
        ("dynamic-10-53-0-30.example.", "A", "10.53.0.30", "A", 120),
        ("a.example.", "A", "10.53.0.4", "A", 120),
        ("dynamic-cafe-cafe--cafe.example", "AAAA", "cafe:cafe::cafe", "AAAA", 3600),
        ("dynamic-cafe-cafe--cafe.example", "ANY", "cafe:cafe::cafe", "AAAA", 3600),
    ],
)
def test_synthrecord_forward(qname, qtype, rname, rtype, ttl):
    msg = dns.message.make_query(qname, qtype)
    res = isctest.query.udp(msg, SERVER)
    isctest.check.noerror(res)
    if qname[-1] != ".":
        qname += "."
    assert len(res.answer) == 1
    assert res.answer[0].ttl == ttl
    assert res.answer[0] == dns.rrset.from_text(qname, ttl, "IN", rtype, rname)


@pytest.mark.parametrize(
    "qname, qtype",
    [("dynamic-10-53-0-44.example.", "AAAA"), ("dynamic-cafe-cafe--cafe.example", "A")],
)
def test_synthrecord_forward_wrongtype(qname, qtype):
    msg = dns.message.make_query(qname, qtype)
    res = isctest.query.udp(msg, SERVER)
    isctest.check.rcode(res, dns.rcode.NOERROR)
    if qname[-1] != ".":
        qname += "."
    assert len(res.answer) == 0


@pytest.mark.parametrize(
    "qname, qtype, rcode",
    [
        ("dynamic-10-53-1-10a.example", "A", dns.rcode.NXDOMAIN),
        ("dynamic-10-53-4-3.example", "A", dns.rcode.NXDOMAIN),
        ("dynamic-10.53.1-3.example", "A", dns.rcode.NXDOMAIN),
        ("dynamic-172-16-0-3.example", "A", dns.rcode.NXDOMAIN),
        ("dynamic-cafe:: .example", "AAAA", dns.rcode.NXDOMAIN),
        ("dynamic-cafe.example", "AAAA", dns.rcode.NXDOMAIN),
        ("dynamic-cafe-cafe--cafez.example", "AAAA", dns.rcode.NXDOMAIN),
        ("dynamic-10-53-1-10", "A", dns.rcode.REFUSED),
        ("dynamic-cafe-cafe--cafe", "AAAA", dns.rcode.REFUSED),
        ("example", "A", dns.rcode.NOERROR),
    ],
)
def test_synthrecord_forward_nodata(qname, qtype, rcode):
    msg = dns.message.make_query(qname, qtype)
    res = isctest.query.udp(msg, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == rcode


@pytest.mark.parametrize(
    "qname, qtype, rcode",
    [
        ("ab.0.53.10.in-addr.arpa.", "PTR", dns.rcode.NXDOMAIN),
        ("1.0.53.10.in-addr.arpa.", "A", dns.rcode.NOERROR),
        ("1.0.53.10.in-addr.arpa.", "AAAA", dns.rcode.NOERROR),
        (
            "z.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa.",
            "PTR",
            dns.rcode.NXDOMAIN,
        ),
        (
            "e.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.f.e.e.b.ip6.arpa",
            "PTR",
            dns.rcode.REFUSED,
        ),
        ("foo.bar", "PTR", dns.rcode.REFUSED),
        ("foo.bar", "A", dns.rcode.REFUSED),
        ("1.64.180.192.in-addr.arpa", "PTR", dns.rcode.REFUSED),
        ("254.63.180.192.in-addr.arpa.", "PTR", dns.rcode.REFUSED),
        ("254.63.180.192.in-addr.arpa.", "A", dns.rcode.REFUSED),
        ("5.1.167.192.in-addr.arpa", "PTR", dns.rcode.REFUSED),
        ("80.80.80.80.in-addr.arpa", "PTR", dns.rcode.REFUSED),
        ("10.1.16.172.in-addr.arpa", "PTR", dns.rcode.REFUSED),
        ("2.1.53.10.in-addr.arpa.", "A", dns.rcode.NOERROR),
        ("5.0.16.172.in-addr.arpa", "PTR", dns.rcode.NXDOMAIN),
        ("1.53.10.in-addr.arpa", "PTR", dns.rcode.NOERROR),
        ("1.53.10.in-addr.arpa", "A", dns.rcode.NOERROR),
        ("1.53.10.in-addr.arpa", "AAAA", dns.rcode.NOERROR),
        ("6.1.168.192.in-addr.arpa", "A", dns.rcode.NOERROR),
        ("5.1.168.192.in-addr.arpa", "A", dns.rcode.NOERROR),
        (
            "e.f.a.c.e.f.a.c.ip6.arpa",
            "PTR",
            dns.rcode.NOERROR,
        ),
        (
            "e.f.a.c.e.f.a.c.ip6.arpa",
            "A",
            dns.rcode.NOERROR,
        ),
        (
            "e.f.a.c.e.f.a.c.ip6.arpa",
            "AAAA",
            dns.rcode.NOERROR,
        ),
        (
            "1.0. . .0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "PTR",
            dns.rcode.NXDOMAIN,
        ),
        (
            "1.0. . .0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa.",
            "PTR",
            dns.rcode.NXDOMAIN,
        ),
    ],
)
def test_synthrecord_reverse_hasnodata(qname, qtype, rcode):
    msg = dns.message.make_query(qname, qtype)
    res = isctest.query.udp(msg, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == rcode


@pytest.mark.parametrize(
    "qname, rcode",
    [
        ("6.1.168.192.in-addr.arpa", dns.rcode.NOERROR),
        ("5.1.168.192.in-addr.arpa", dns.rcode.NOERROR),
    ],
)
def test_synthrecord_reverse_delegate(qname, rcode):
    msg = dns.message.make_query(qname, "PTR")
    res = isctest.query.udp(msg, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == rcode
    assert len(res.authority) == 1
    assert (
        res.authority[0].to_text() == "1.168.192.in-addr.arpa. 120 IN NS ns2.example."
    )


# Tests the any allow-syth (as the whole subnet matching the zone is accepted)
# as well as the TTL
@pytest.mark.parametrize(
    "qname, rname",
    [
        (
            "f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.ip6.arpa",
            "dynamicdefaults-ffff-ffff-ffff-ffff-ffff-ffff-ffff-ffff.example.",
        ),
        (
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.f.f.f.f.ip6.arpa",
            "dynamicdefaults-ffff-ffff--0.example.",
        ),
    ],
)
def test_synthrecord_defaults(qname, rname):
    ttl = 300
    msg = dns.message.make_query(qname, "PTR")
    res = isctest.query.udp(msg, SERVER)
    isctest.check.noerror(res)
    if qname[-1] != ".":
        qname += "."
    assert len(res.answer) == 1
    assert res.answer[0].ttl == ttl
    assert res.answer[0] == dns.rrset.from_text(qname, ttl, "IN", "PTR", rname)


@pytest.mark.parametrize(
    "qname, qtype, rcode, answerscount",
    [
        ("55.0.53.10.in-addr.arpa", "ANY", dns.rcode.NOERROR, 1),
        ("55.1.53.10.in-addr.arpa", "ANY", dns.rcode.NXDOMAIN, 0),
        (
            "e.f.a.c.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.ip6.arpa",
            "ANY",
            dns.rcode.NOERROR,
            1,
        ),
    ],
)
def test_synthrecord_reverse_anysoa(qname, qtype, rcode, answerscount):
    msg = dns.message.make_query(qname, qtype)
    res = isctest.query.udp(msg, SERVER)
    assert len(res.answer) == answerscount
    assert res.rcode() == rcode


def build_synthetic_name_v4(prefix, ip, domain):
    return dns.name.from_text(f"{prefix}{format(ip).replace('.', '-')}.{domain}")


def build_synthetic_name_v6(prefix, ip, domain):
    ipencoded = format(ip).replace(":", "-")
    if ipencoded[:1] == "-":
        ipencoded = f"0{ipencoded}"
    if ipencoded[-1:] == "-":
        ipencoded = f"{ipencoded}0"
    return dns.name.from_text(f"{prefix}{ipencoded}.{domain}")


example_domain = dns.name.from_text("example.")


@given(domain=dns_names())
def test_synthrecord_reverse_randomdomains(domain):
    assume(
        not (
            domain.is_subdomain(ipv4_reverse_domain)
            or domain.is_subdomain(ipv6_reverse_domain)
            or domain.is_subdomain(example_domain)
        )
    )
    query = dns.message.make_query(domain, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.REFUSED


@given(ip=ip_addresses(network="10.53.0.0/24"))
def test_sythreverse_noerror_hasdata_v4(ip):
    assume(ip not in [IPv4Address("10.53.0.28"), IPv4Address("10.53.0.4")])
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.NOERROR
    assert res.answer == [
        dns.rrset.from_text(
            ip.reverse_pointer + ".",
            0,
            "IN",
            "PTR",
            build_synthetic_name_v4("dynamic-", ip, "example").to_text(),
        )
    ]


@given(ip=ip_addresses(network="10.53.2.0/24"))
def test_sythreverse_refused_v4(ip):
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.REFUSED


arpa_cafecafe = dns.name.from_text("e.f.a.c.e.f.a.c.ip6.arpa.")
arpa_zeros16 = dns.name.from_text("0.0.0.0.ip6.arpa.")
arpa_ffff16 = dns.name.from_text("f.f.f.f.ip6.arpa.")


@given(ip=ip_addresses(v=6))
def test_sythreverse_refused_v6(ip):
    assume(not dns.name.from_text(ip.reverse_pointer).is_subdomain(arpa_cafecafe))
    assume(not dns.name.from_text(ip.reverse_pointer).is_subdomain(arpa_zeros16))
    assume(not dns.name.from_text(ip.reverse_pointer).is_subdomain(arpa_ffff16))
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.REFUSED


@pytest.mark.parametrize(
    "addr, expected",
    [
        ("cafe:cafe::", "dynamic-cafe-cafe--0.example."),
        ("::1", "dynamic-0--1.example."),
        ("::", "dynamic-0--0.example."),
    ],
)
def test_synthreverse_idn_compat(addr, expected):
    ip = IPv6Address(addr)
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.NOERROR
    assert res.answer == [
        dns.rrset.from_text(ip.reverse_pointer + ".", 0, "IN", "PTR", expected)
    ]


# `@example(ip="::")` ensure the IP `::` is always generated. Just to make sure
# the way we generate a name based on a prefix, IPv6 and domain is correct
# regarding the expected generated value from the plugin: because of IDN, a
# label can't have a leading or trailing '-'.
@example(ip=IPv6Address("::"))
@given(ip=ip_addresses(network="cafe:cafe::/32"))
def test_sythreverse_noerror_hasdata_v6(ip):
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.NOERROR
    assert res.answer == [
        dns.rrset.from_text(
            ip.reverse_pointer + ".",
            0,
            "IN",
            "PTR",
            build_synthetic_name_v6("dynamic-", ip, "example").to_text(),
        )
    ]


@given(ip=ip_addresses(network="10.53.1.0/24"))
def test_sythreverse_unallowed_subnet_v4(ip):
    # allow-nets is 10.53.1.0/29, so only addresses below 10.53.1.9 are allowed
    # to have a synthetic record (_allow_subnet_v4 below checks the opposite)
    assume(ip > IPv4Address("10.53.1.8"))
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(ip=ip_addresses(network="10.53.1.0/29"))
def test_sythreverse_allowed_subnet_v4(ip):
    query = dns.message.make_query(ip.reverse_pointer, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert res.rcode() == dns.rcode.NOERROR
    assert res.answer == [
        dns.rrset.from_text(
            ip.reverse_pointer + ".",
            0,
            "IN",
            "PTR",
            build_synthetic_name_v4("dynamic-", ip, "example").to_text(),
        )
    ]


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        suffix=dns.name.from_text("1.53.10.in-addr.arpa."), min_labels=8, max_labels=34
    )
)
def test_sythreverse_arpa_v4_nxdomain_toomanylabel(domain):
    query = dns.message.make_query(domain, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        prefix=dns.name.from_text("dynamic-10-53-0-20"),
        suffix=dns.name.from_text("example"),
        min_labels=4,
        max_labels=34,
    )
)
def test_sythforward_arpa_v4_nxdomain_toomanylabel(domain):
    query = dns.message.make_query(domain, "A")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        prefix=dns.name.from_text("dynamic-cafe-cafe--cafe"),
        suffix=dns.name.from_text("example"),
        min_labels=4,
        max_labels=34,
    )
)
def test_sythforward_arpa_v6_nxdomain_toomanylabel(domain):
    query = dns.message.make_query(domain, "AAAA")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        prefix=dns.name.from_text("dynamic-cafe--cafe--cafe"),
        suffix=dns.name.from_text("example"),
        min_labels=2,
        max_labels=34,
    )
)
def test_sythforward_arpa_v6_nxdomain_unallowednet(domain):
    query = dns.message.make_query(domain, "AAAA")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        suffix=dns.name.from_text("a.e.f.a.c.e.f.a.c.ip6.arpa."), max_labels=34
    )
)
def test_sythreverse_arpa_v6_nxdomain_toofewlabels(domain):
    query = dns.message.make_query(domain, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


@given(
    domain=isctest.hypothesis.strategies.dns_names(
        suffix=dns.name.from_text("e.f.a.c.e.f.a.c.ip6.arpa."), min_labels=36
    )
)
def test_sythreverse_arpa_v6_nxdomain_toomanylabels(domain):
    query = dns.message.make_query(domain, "PTR")
    res = isctest.query.udp(query, SERVER)
    assert len(res.answer) == 0
    assert res.rcode() == dns.rcode.NXDOMAIN


def test_synthrecord_inview(ns1, templates):
    templates.render("ns1/named.conf", {"inview": True})
    with ns1.watch_log_from_here() as watcher:
        cmd = ns1.rndc("reconfig", raise_on_exception=False)
        assert cmd.rc != 0
        watcher.wait_for_line("'synthrecord' must be configured as a zone plugin")


def test_synthrecord_toolongprefix(ns1, templates):
    templates.render("ns1/named.conf", {"toolongprefix": True})
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reconfig")
        watcher.wait_for_line("running")
    ip = IPv4Address("10.53.0.8")
    with ns1.watch_log_from_here() as watcher:
        query = dns.message.make_query(ip.reverse_pointer, "PTR")
        res = isctest.query.udp(query, SERVER)
        assert res.rcode() == dns.rcode.NXDOMAIN
        watcher.wait_for_line(
            "synthrecord cannot create reverse answer name: ran out of space"
        )
