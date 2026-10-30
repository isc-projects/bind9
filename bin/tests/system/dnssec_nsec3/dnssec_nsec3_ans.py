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

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset


def base32hex_delta(base32_hash: str, delta: int) -> str:
    base32_hash_raw = base64.b32hexdecode(base32_hash)
    base32_hash_raw_length = len(base32_hash_raw)
    base32_hash_value = int.from_bytes(base32_hash_raw, "big")
    base32_hash_value_with_delta = base32_hash_value + delta
    base32_hash_value_with_delta %= 1 << (8 * base32_hash_raw_length)
    base32_hash_raw_with_delta = base32_hash_value_with_delta.to_bytes(
        base32_hash_raw_length, "big"
    )
    base32_hash_with_delta = base64.b32hexencode(base32_hash_raw_with_delta)
    return base32_hash_with_delta.decode("ascii")


def rrset(
    owner: dns.name.Name | str,
    rtype: dns.rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, ttl, dns.rdataclass.IN, rtype, rdata)


def minimal_covering_nsec3(
    name: dns.name.Name, origin: dns.name.Name
) -> dns.rrset.RRset:
    nsec3_hash = dns.dnssec.nsec3_hash(name, None, 0, 1)
    nsec3_hash_just_before = base32hex_delta(nsec3_hash, -1)
    nsec3_hash_just_after = base32hex_delta(nsec3_hash, +1)
    nsec3_owner = dns.name.from_text(nsec3_hash_just_before, origin=origin)
    return rrset(
        nsec3_owner,
        dns.rdatatype.NSEC3,
        f"1 0 0 - {nsec3_hash_just_after} TXT RRSIG",
    )
