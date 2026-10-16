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

"""
Model tests for the real C vecheader implementation.

Run through Meson: meson test -C builddir --suite hypothesis --print-errorlogs
Each protobuf request is independent; only the adapter process is reused.
"""

import os
import struct
import sys

from isc_hypothesis import RestartingProtobufServer

try:
    from hypothesis import example, given, settings
    from hypothesis import strategies as st

    import dns.rdatatype

    from isctest.hypothesis.strategies import dns_names
except ModuleNotFoundError as error:
    print(f"skipping vecheader hypothesis tests: {error}", file=sys.stderr)
    sys.exit(77)

import vecheader_pb2 as proto  # pylint: disable=import-error,wrong-import-position

OPAQUE_TYPE = dns.rdatatype.RdataType(65280)

settings.register_profile(
    "vecheader-ci", max_examples=300, deadline=None, derandomize=True
)
settings.register_profile("extended", max_examples=3000, deadline=None)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "vecheader-ci"))

server = None


@st.composite
def owners(draw):
    if draw(st.booleans()):
        return None
    name = draw(dns_names()).to_wire()
    return name.lower() if draw(st.booleans()) else name


@st.composite
def headers(draw, records):
    values = draw(st.lists(st.sampled_from(records), max_size=15))
    header = proto.Header(
        records=values,
        # A record's flag is deterministic across duplicates within an input;
        # differing flags across operands still exercise left-wins merging.
        offline=[False] * len(values),
        ttl=draw(st.integers(0, 2**32 - 1)),
        trust=draw(st.integers(0, 10)),
        serial=draw(st.integers(0, 2**32 - 1)),
        resign=draw(st.booleans()),
        resign_time=draw(st.integers(0, 2**40)),
    )
    owner = draw(owners())
    if owner is not None:
        header.owner = owner
    return header


@st.composite
def cases(draw):
    rrtype = draw(
        st.sampled_from(
            [
                dns.rdatatype.A,
                dns.rdatatype.AAAA,
                dns.rdatatype.TXT,
                dns.rdatatype.RRSIG,
                dns.rdatatype.CNAME,
                OPAQUE_TYPE,
            ]
        )
    )
    tokens = draw(st.lists(st.integers(0, 15), min_size=1, max_size=8, unique=True))

    def wire(token):
        if rrtype == dns.rdatatype.A:
            return bytes([192, 0, 2, token])
        if rrtype == dns.rdatatype.AAAA:
            return bytes(15) + bytes([token])
        if rrtype == dns.rdatatype.TXT:
            return bytes([token]) + bytes([token]) * token
        if rrtype == dns.rdatatype.CNAME:
            return b"\x01" + bytes([97 + token]) + b"\x00"
        if rrtype == dns.rdatatype.RRSIG:
            # A/algorithm/labels/TTL/expiration/inception/key tag/root signer.
            return (
                struct.pack("!HBBIIIH", dns.rdatatype.A, 8, 0, 300, 1000, 0, token)
                + b"\x00sig"
            )
        return bytes([token]) * token

    pool = [wire(token) for token in tokens]
    left = draw(headers(pool))
    right = draw(headers(pool))
    if rrtype == dns.rdatatype.CNAME:
        # Valid singleton operands; union can still violate singleton rules.
        del left.records[1:]
        del left.offline[1:]
        del right.records[1:]
        del right.offline[1:]
    if rrtype == dns.rdatatype.RRSIG:
        for header in (left, right):
            flag = draw(st.booleans())
            header.offline[:] = [flag] * len(header.records)
    count = len(set(left.records) | set(right.records))
    limit = draw(st.sampled_from(sorted({0, 1, max(1, count - 1), count, count + 1})))
    return rrtype, left, right, limit


def contents(header):
    return dict(zip(header.records, header.offline))


def check_header(response, expected, metadata, owner, rrtype):
    assert response.HasField("header")
    actual = response.header
    # For these generated types, canonical DNSSEC order is wire byte order.
    assert list(actual.records) == sorted(expected)
    assert list(actual.offline) == [expected[key] for key in sorted(expected)]
    assert response.count == len(expected)
    assert response.raw_length == sum(
        2 + len(key) + (rrtype == dns.rdatatype.RRSIG) for key in expected
    )
    assert response.size == response.header_size + response.raw_length
    assert response.type == rrtype
    assert response.covers == (
        dns.rdatatype.A if rrtype == dns.rdatatype.RRSIG else dns.rdatatype.NONE
    )
    for field in ("ttl", "trust", "serial", "resign", "resign_time"):
        assert getattr(actual, field) == getattr(metadata, field), field
    name = owner.owner if owner.HasField("owner") else None
    bitmap = bytearray(32)
    if name is not None:
        for index, byte in enumerate(name):
            if 65 <= byte <= 90:
                bitmap[index // 8] |= 1 << (index % 8)
    assert response.case_set == (name is not None)
    assert response.case_lower == (name is not None and name == name.lower())
    assert response.bitmap == bytes(bitmap)
    if name is not None:
        assert response.applied_owner == name


@given(cases(), st.integers(0, 3))
def test_merge(case, flags):
    rrtype, left, right, limit = case
    a, b = contents(left), contents(right)
    expected = b | a  # Old RDATA wins on equality, including offline metadata.
    if limit and len(expected) > limit:
        result = proto.TOO_MANY_RECORDS
    elif flags & 2 and a.keys() & b.keys():
        result = proto.NOT_EXACT
    elif b.keys() <= a.keys() and not flags & 1:
        result = proto.UNCHANGED
    elif rrtype == dns.rdatatype.CNAME and len(expected) > 1:
        result = proto.SINGLETON
    else:
        result = proto.SUCCESS
    response = server.command(
        proto.Request(
            merge=proto.Merge(
                type=rrtype, left=left, right=right, flags=flags, limit=limit
            )
        )
    )
    assert response.result == result
    if result == proto.SUCCESS:
        check_header(response, expected, right, left, rrtype)
    else:
        assert not response.HasField("header")


@given(cases(), st.booleans())
def test_subtract(case, exact):
    rrtype, left, right, _ = case
    a, b = contents(left), contents(right)
    expected = {key: flag for key, flag in a.items() if key not in b}
    if exact and not b.keys() <= a.keys():
        result = proto.NOT_EXACT
    elif not expected:
        result = proto.NXRRSET
    elif expected == a:
        result = proto.UNCHANGED
    else:
        result = proto.SUCCESS
    response = server.command(
        proto.Request(
            subtract=proto.Subtract(
                type=rrtype, left=left, right=right, flags=2 if exact else 0
            )
        )
    )
    assert response.result == result
    if result == proto.SUCCESS:
        check_header(response, expected, left, left, rrtype)
    else:
        assert not response.HasField("header")


@given(cases())
def test_construction(case):
    rrtype, left, _, _ = case
    response = server.command(
        proto.Request(construct=proto.Construct(type=rrtype, header=left))
    )
    assert response.result == proto.SUCCESS
    check_header(response, contents(left), left, left, rrtype)


@given(st.integers(65507, 65515))
@example(65510)
@example(65511)
def test_size_boundary(length):
    # Opaque RDATA avoids type-specific parsing; two length bytes count too.
    header = proto.Header(records=[bytes(length)], offline=[False])
    response = server.command(
        proto.Request(construct=proto.Construct(type=OPAQUE_TYPE, header=header))
    )
    expected = proto.SUCCESS if length + 2 <= 65512 else proto.NO_SPACE
    assert response.result == expected
    if expected == proto.SUCCESS:
        check_header(response, contents(header), header, header, OPAQUE_TYPE)


@given(st.integers(32750, 32760))
def test_merge_size_boundary(length):
    left = proto.Header(records=[b"a" * length], offline=[False])
    right = proto.Header(records=[b"b" * length], offline=[False])
    response = server.command(
        proto.Request(merge=proto.Merge(type=OPAQUE_TYPE, left=left, right=right))
    )
    expected = proto.SUCCESS if 2 * (length + 2) <= 65512 else proto.NO_SPACE
    assert response.result == expected
    if expected == proto.SUCCESS:
        check_header(
            response, contents(left) | contents(right), right, left, OPAQUE_TYPE
        )


@given(st.integers(2, 30), st.booleans())
def test_overlapping_limit(count, force):
    records = [bytes([192, 0, 2, i]) for i in range(count)]
    left = proto.Header(records=records[:-1], offline=[False] * (count - 1))
    right = proto.Header(records=records[-2:], offline=[False] * 2)
    response = server.command(
        proto.Request(
            merge=proto.Merge(
                type=dns.rdatatype.A,
                left=left,
                right=right,
                limit=count,
                flags=1 if force else 0,
            )
        )
    )
    assert response.result == proto.SUCCESS
    check_header(
        response, contents(left) | contents(right), right, left, dns.rdatatype.A
    )
    response = server.command(
        proto.Request(
            merge=proto.Merge(
                type=dns.rdatatype.A,
                left=right,
                right=right,
                limit=2,
                flags=1 if force else 0,
            )
        )
    )
    assert response.result == (proto.SUCCESS if force else proto.UNCHANGED)
    if force:
        check_header(response, contents(right), right, right, dns.rdatatype.A)


@given(owners())
@example(b"\x07ExAmPlE\x03com\x00")
@example(b"\x07example\x03com\x00")
def test_subtract_owner_case(owner):
    left = proto.Header(
        records=[b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02"], offline=[False, False]
    )
    if owner is not None:
        left.owner = owner
    right = proto.Header(records=[left.records[0]], offline=[False])
    response = server.command(
        proto.Request(
            subtract=proto.Subtract(type=dns.rdatatype.A, left=left, right=right)
        )
    )
    assert response.result == proto.SUCCESS
    check_header(response, {left.records[1]: False}, left, left, dns.rdatatype.A)


@given(st.integers(1, 20), st.integers(0, 21))
def test_construction_limit(count, limit):
    # Construction currently checks input count, before deduplication.
    header = proto.Header(
        records=[b"\xc0\x00\x02\x01"] * count, offline=[False] * count
    )
    response = server.command(
        proto.Request(
            construct=proto.Construct(type=dns.rdatatype.A, header=header, limit=limit)
        )
    )
    expected = proto.TOO_MANY_RECORDS if limit and count > limit else proto.SUCCESS
    assert response.result == expected
    if expected == proto.SUCCESS:
        check_header(response, contents(header), header, header, dns.rdatatype.A)


@given(cases())
def test_copy(case):
    rrtype, left, _, _ = case
    response = server.command(proto.Request(copy=proto.Copy(type=rrtype, header=left)))
    assert response.result == proto.SUCCESS
    # The copy constructor initializes a fresh header from rdataset fields;
    # serial, case and resign metadata are deliberately not copied.
    fresh = proto.Header(ttl=left.ttl, trust=left.trust)
    check_header(response, contents(left), fresh, fresh, rrtype)
    if left.HasField("owner"):
        assert response.applied_owner == left.owner.lower()


@given(cases(), dns_names())
def test_set_owner_case(case, name):
    rrtype, left, _, _ = case
    header = proto.Header()
    header.CopyFrom(left)
    header.ClearField("owner")
    owner = name.to_wire()
    response = server.command(
        proto.Request(
            set_owner_case=proto.SetOwnerCase(type=rrtype, header=header, owner=owner)
        )
    )
    assert response.result == proto.SUCCESS
    header.owner = owner
    check_header(response, contents(header), header, header, rrtype)


if __name__ == "__main__":
    with RestartingProtobufServer(
        os.environ["VECHEADER_SERVER"], proto.Response
    ) as server:
        for test in (
            test_construction,
            test_merge,
            test_subtract,
            test_size_boundary,
            test_merge_size_boundary,
            test_overlapping_limit,
            test_subtract_owner_case,
            test_construction_limit,
            test_copy,
            test_set_owner_case,
        ):
            test()
            print(f"{test.__name__}: passed", flush=True)
