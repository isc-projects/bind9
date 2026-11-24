# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import time

from dns.edns import EDECode

import dns.edns
import dns.message
import dns.rcode
import dns.rdatatype
import pytest

import isctest


@pytest.mark.parametrize(
    "server,qname,rd",
    [
        pytest.param("10.53.0.4", "mx-only.tld.", False, id="authoritative"),
        pytest.param("10.53.0.4", "nxdomain-any.tld.", False, id="nxdomain"),
        pytest.param("10.53.0.5", "mx-only.tld.", True, id="recursive"),
        pytest.param("10.53.0.5", "mx-only.tld.", False, id="non-recursive"),
    ],
)
def test_any_udp_truncated(server, qname, rd):
    # ANY queries are only answered over TCP. Over UDP the response is
    # always empty and truncated, whatever the response over TCP would
    # be: authoritative data or NXDOMAIN (ns4), REFUSED from a resolver
    # (ns5) when recursion is requested, or the cache contents when it
    # is not.
    msg = isctest.query.create(qname, "ANY", rd=rd, dnssec=False)
    res = isctest.query.udp(msg, server)
    isctest.check.noerror(res)
    isctest.check.tcflag(res)
    isctest.check.noaaflag(res)
    isctest.check.empty_answer(res)
    isctest.check.empty_authority(res)
    isctest.check.empty_additional(res)


def test_any_udp_server_cookie():
    # A valid server cookie proves that the client address is not
    # spoofed, so the ANY query is answered over UDP.  Get the server
    # cookie with a query of another type first.
    client_cookie = dns.edns.GenericOption(dns.edns.OptionType.COOKIE, b"\x01" * 8)
    msg = isctest.query.create("mx-only.tld.", "MX", rd=False, dnssec=False)
    msg.use_edns(edns=0, options=[client_cookie])
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    cookies = [
        option.to_wire()
        for option in res.options
        if option.otype == dns.edns.OptionType.COOKIE
    ]
    assert len(cookies) == 1 and len(cookies[0]) > 8, res

    # A client cookie alone proves nothing.
    msg = isctest.query.create("mx-only.tld.", "ANY", rd=False, dnssec=False)
    msg.use_edns(edns=0, options=[client_cookie])
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.tcflag(res)
    isctest.check.empty_answer(res)

    full_cookie = dns.edns.GenericOption(dns.edns.OptionType.COOKIE, cookies[0])
    msg = isctest.query.create("mx-only.tld.", "ANY", rd=False, dnssec=False)
    msg.use_edns(edns=0, options=[full_cookie])
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.notcflag(res)
    isctest.check.aaflag(res)
    assert [rrset.rdtype for rrset in res.answer] == [dns.rdatatype.MX]


def test_any_tcp_authoritative():
    # The authoritative answer withheld over UDP is given over TCP.
    msg = isctest.query.create("mx-only.tld.", "ANY", rd=False, dnssec=False)
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.notcflag(res)
    isctest.check.aaflag(res)
    assert [rrset.rdtype for rrset in res.answer] == [dns.rdatatype.MX]


def test_resolver_any_mx_only(ns5):
    ns5.rndc("flush")

    # A cache miss cannot tell us which types exist at the name. Refuse
    # ANY instead of substituting an address query or a NODATA answer.
    msg = isctest.query.create("mx-only.tld.", "ANY", dnssec=False)
    res = isctest.query.tcp(msg, ns5.ip, expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(res)
    isctest.check.empty_answer(res)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)

    # An explicit MX query still resolves. Refuse ANY consistently even
    # after that RRset has been cached.
    msg = isctest.query.create("mx-only.tld.", "MX", dnssec=False)
    mx = isctest.query.tcp(msg, ns5.ip)
    isctest.check.noerror(mx)
    assert len(mx.answer) == 1
    assert mx.answer[0].rdtype == dns.rdatatype.MX

    msg = isctest.query.create("mx-only.tld.", "ANY", dnssec=False)
    res = isctest.query.tcp(msg, ns5.ip, expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(res)
    isctest.check.empty_answer(res)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)


def test_resolver_any_norecurse(ns5):
    ns5.rndc("flush")

    # Without RD, an ANY query only inspects the cache. On a cache miss
    # it is handled like a non-recursive query of any other type; it is
    # not refused.
    rcodes = {}
    for qtype in ("MX", "ANY"):
        msg = isctest.query.create("mx-only.tld.", qtype, rd=False, dnssec=False)
        res = isctest.query.tcp(msg, ns5.ip)
        isctest.check.empty_answer(res)
        rcodes[qtype] = res.rcode()
    assert rcodes["ANY"] == rcodes["MX"]
    assert rcodes["ANY"] != dns.rcode.REFUSED

    # Once a recursive query has populated the cache, the non-recursive
    # ANY query returns what is cached at the name.
    msg = isctest.query.create("mx-only.tld.", "MX", dnssec=False)
    mx = isctest.query.tcp(msg, ns5.ip)
    isctest.check.noerror(mx)

    msg = isctest.query.create("mx-only.tld.", "ANY", rd=False, dnssec=False)
    res = isctest.query.tcp(msg, ns5.ip)
    isctest.check.noerror(res)
    assert [rrset.rdtype for rrset in res.answer] == [dns.rdatatype.MX]

    # A cached NXDOMAIN is returned for a non-recursive ANY query, too.
    msg = isctest.query.create("nxdomain-any.tld.", "A", dnssec=False)
    res = isctest.query.tcp(msg, ns5.ip, expected_rcode=dns.rcode.NXDOMAIN)
    isctest.check.nxdomain(res)

    msg = isctest.query.create("nxdomain-any.tld.", "ANY", rd=False, dnssec=False)
    res = isctest.query.tcp(msg, ns5.ip, expected_rcode=dns.rcode.NXDOMAIN)
    isctest.check.nxdomain(res)
    isctest.check.empty_answer(res)


def test_resolver_cache_reloadfails(ns1, templates):
    ns1.rndc("flush")
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert res.answer[0].ttl == 300
    templates.render(
        "ns1/named.conf", {"wrongoption": True}, template="ns1/named2.conf.j2"
    )

    # The first reload fails, and the old cache list will be preserved
    cmd = ns1.rndc("reload", raise_on_exception=False)
    assert cmd.rc != 0

    templates.render("ns1/named.conf", {"wrongoption": False})
    # The second reload succeed, and the cache is still there, as preserved
    # from the old cache list
    ns1.rndc("reload")
    time.sleep(3)
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    # The ttl being lower than 300 (provided by fake authoritative) proves
    # the cache is still in use
    assert res.answer[0].ttl < 300


# GL#5930
def test_resolver_dname_target_filter_attack():
    # Control check - this should return 'attack.example.net. DNAME org.',
    # which then should result in resolving 'www.example.org. AAAA', which
    # should be SERVAIL because example.org is in 'deny-answer-aliases'.
    msg = isctest.query.create("www.example.attack.example.net.", "AAAA")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.servfail(res)

    # Execute the attack - this should return 'attack.example.net. DNAME org.',
    # which then should result in resolving isc.org and caching the DNAME.
    msg = isctest.query.create("isc.attack.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    answer = """;ANSWER
attack.example.net. 300 IN DNAME org.
isc.attack.example.net. 300 IN CNAME isc.org.
isc.org. 300 IN A 1.2.3.4
;AUTHORITY
;ADDITIONAL
"""
    expected_answer = dns.message.from_text(answer)
    isctest.check.noerror(res)
    isctest.check.rrsets_equal(res.answer, expected_answer.answer)
    isctest.check.rrsets_equal(res.authority, expected_answer.authority)
    isctest.check.rrsets_equal(res.additional, expected_answer.additional)

    # Vulnerability check - this should return 'attack.example.net. DNAME org.'
    # which then should result in resolving 'www.example.org. A', which
    # should still be SERVAIL because example.org is in 'deny-answer-aliases',
    # unless the attack on the previous step was successful.
    msg = isctest.query.create("www.example.attack.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.servfail(res)

    # Exception check - this should return 'gooddname.example.net. DNAME org.'
    # which then should result in resolving 'www.example.org. A', which
    # should be NOERROR because while example.org is in 'deny-answer-aliases',
    # gooddname.example.net is in the exceptions list.
    msg = isctest.query.create("www.example.gooddname.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)


def test_resolver_any_refused(ns1):
    ns1.rndc("flush")

    # A resolver refuses recursive ANY queries with REFUSED and EDE 21
    # (Not Supported), without looking the name up or sending anything
    # upstream
    msg = isctest.query.create("www.example.org.", "ANY")
    res = isctest.query.tcp(msg, "10.53.0.1", expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(res)
    isctest.check.empty_answer(res)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)

    # ...including when the cache holds records for the queried name
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert res.answer[0].rdtype == dns.rdatatype.A

    msg = isctest.query.create("www.example.org.", "ANY")
    res = isctest.query.tcp(msg, "10.53.0.1", expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(res)
    isctest.check.empty_answer(res)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)


def test_resolver_any_refused_below_delegation():
    # ns7 is authoritative for sub.tld1, which delegates bar.sub.tld1
    # elsewhere; an ANY query for a name below that delegation could
    # only be answered by recursing, so it is refused when recursion
    # is requested...
    msg = isctest.query.create("foo.bar.sub.tld1.", "ANY")
    res = isctest.query.tcp(msg, "10.53.0.7", expected_rcode=dns.rcode.REFUSED)
    isctest.check.refused(res)
    isctest.check.empty_answer(res)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)

    # ...and answered with the referral when it is not
    msg = isctest.query.create("foo.bar.sub.tld1.", "ANY", rd=False)
    res = isctest.query.tcp(msg, "10.53.0.7")
    isctest.check.noerror(res)
    isctest.check.empty_answer(res)
    assert any(
        rrset.rdtype == dns.rdatatype.NS and str(rrset.name) == "bar.sub.tld1."
        for rrset in res.authority
    ), f"expected a referral for bar.sub.tld1: {res}"
