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

import base64

import dns.message

import isctest
import isctest.mark

pytestmark = [
    isctest.mark.with_curl,
    isctest.mark.with_libnghttp2,
    isctest.mark.with_fips_dh,
]


def doh_get_headers(ip, port, qname, qtype):
    """
    Send a DoH GET request (RFC 8484 "dns" query parameter) with curl
    and return the HTTP response headers.
    """
    query = dns.message.make_query(qname, qtype, id=0)
    dns_param = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode()
    curl = isctest.run.EnvCmd(
        "CURL", "--silent --show-error --insecure --dump-header - --output /dev/null"
    )
    return curl(f"https://{ip}:{port}/dns-query?dns={dns_param}").out


def test_max_age_positive_answer(ns1, named_httpsport):
    headers = doh_get_headers(ns1.ip, named_httpsport, "example.", "SOA")
    assert "HTTP/2 200" in headers
    assert "cache-control: max-age=86400" in headers


def test_max_age_negative_answer(ns1, named_httpsport):
    headers = doh_get_headers(ns1.ip, named_httpsport, "fake.example.", "TXT")
    assert "HTTP/2 200" in headers
    assert "cache-control: max-age=3600" in headers
