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

import dns.rcode

import isctest


def test_showconf(ns1):
    # Basic testing of rndc showconf
    msg = isctest.query.create("a.example.com", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.rcode(res, dns.rcode.NOERROR)

    effectiveconfig = ns1.rndc("showconf -effective")
    assert 'zone "example.com"' in effectiveconfig.out
    assert 'view "_bind" chaos {' in effectiveconfig.out

    # builtin-trust-anchors is non documented and internal clause only, it must
    # not be visible.
    assert "builtin-trust-anchors" not in effectiveconfig.out

    # Dynamically added zones are not visible from the effectiveconfig
    zonedata = '"added.example" { type primary; file "example.db"; };'
    ns1.rndc(f"addzone {zonedata}")

    msg = isctest.query.create("a.added.example", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.rcode(res, dns.rcode.NOERROR)

    effectiveconfig = ns1.rndc("showconf -effective")
    assert 'zone "added.example"' not in effectiveconfig.out

    userconfig = ns1.rndc("showconf -user")
    assert 'zone "example.com"' in userconfig.out
    assert 'view "_bind" chaos {' not in userconfig.out

    builtinconfig = ns1.rndc("showconf -builtin")
    assert len(userconfig.out.split()) < len(builtinconfig.out.split())
    assert len(builtinconfig.out.split()) < len(effectiveconfig.out.split())

    # Errors handling
    response = ns1.rndc("showconf -idontexist", raise_on_exception=False)
    assert response.rc != 0
    assert "rndc: 'showconf' failed: syntax error" in response.err

    response = ns1.rndc("showconf", raise_on_exception=False)
    assert response.rc != 0
    assert "rndc: 'showconf' failed: unexpected end of input" in response.err
