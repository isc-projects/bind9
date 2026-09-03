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

import struct

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

import isctest


def make_sig0_query(qname_str, key_name_str, truncate_sig):
    root = dns.name.from_text(".")
    qname = dns.name.from_text(qname_str)
    query = dns.message.make_query(qname, dns.rdatatype.A)
    query.flags |= dns.flags.RD

    # Constants so that they don't affect the signature
    query.id = 1234
    key_tag = 11622
    expiration = 0x7FFFFFFF
    inception = 0
    signer_name = dns.name.from_text(key_name_str)
    # Precalculated HMAC
    signature = bytes.fromhex(
        "c5bc8e6b21adca9245d1c9e03324ff30d9fb2ef095e9212ea386161a19f5d413"
    )
    if truncate_sig:
        signature = signature[0:1]

    # Construct SIG RDATA header (0=SIG(0), 163=HMACSHA256, 0=Labels)
    sig_rdata_header = struct.pack(
        "!HBBIIIH", 0, 163, 0, 0, expiration, inception, key_tag
    )

    sig_rdata_pre_sig = sig_rdata_header + signer_name.to_wire()

    # Create the SIG RR
    full_sig_rdata = sig_rdata_pre_sig + signature
    sig_rr = dns.rdata.from_wire(
        dns.rdataclass.ANY,
        dns.rdatatype.SIG,
        full_sig_rdata,
        0,
        len(full_sig_rdata),
    )
    sig_rrset = dns.rrset.from_rdata(root, 0, sig_rr)
    query.additional.append(sig_rrset)

    return query


# GL#6120: SIG(0) should not support HMAC, and even if it does, truncated
# signatures should not be accepted
def test_sig0_hmac():
    query_full = make_sig0_query("test.example2.", "sig0.example2.", False)
    res = isctest.query.tcp(query_full, "10.53.0.1")
    isctest.check.servfail(res)

    query_truncared = make_sig0_query("test.example2.", "sig0.example2.", True)
    res = isctest.query.tcp(query_truncared, "10.53.0.1")
    isctest.check.servfail(res)
