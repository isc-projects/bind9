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

from dns import rdatatype, update

import pytest

import isctest
import isctest.mark

pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.bk",
        "*/*.conf",
        "*/*.db",
        "*/*.jnl",
        "*/*.jbk",
        "*/*.key",
        "*/*.signed",
    ]
)


# wait for all of the signed zones to get their signatures
# before running any tests.
@pytest.fixture(scope="module", autouse=True)
def after_servers_start():
    for zone in ("nsec", "nsec3", "optout"):
        msg = isctest.query.create(zone, "soa")
        while True:
            res = isctest.query.tcp(msg, "10.53.0.1")
            if len(res.answer) == 1:
                continue
            time.sleep(1)
            break


def getfrom(file):
    with open(file, encoding="utf-8") as f:
        return f.read().strip()


@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_capture_signed(zone):
    # This "test" doesn't test anything, it just dumps the signed
    # version of the test zones into the pytest log so they can be
    # used for debugging when needed.
    msg = isctest.query.create(f"{zone}", "axfr")
    isctest.query.tcp(msg, "10.53.0.1")


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "qtype",
    ["soa", "ns", "ds", 61440],
)
@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_apex_answers(zone, qtype):
    signed = zone != "unsigned"

    msg = isctest.query.create(zone, qtype)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.aaflag(res)
    if qtype == "soa":
        isctest.check.rr_count_eq(res.answer, 2 if signed else 1)
        isctest.check.rr_count_eq(res.additional, 0)
        isctest.check.rr_count_eq(res.authority, 0)
    elif qtype == "ns":
        isctest.check.rr_count_eq(res.answer, 2 if signed else 1)
        isctest.check.rr_count_eq(res.additional, 2 if signed else 1)
        isctest.check.rr_count_eq(res.authority, 0)
    elif qtype in ("ds", 61440):
        isctest.check.rr_count_eq(res.answer, 0)
        isctest.check.rr_count_eq(res.additional, 0)
        isctest.check.rr_count_eq(res.authority, 4 if signed else 1)


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "do, de",
    [
        [True, True],
        [True, False],
        [False, True],
        [False, False],
    ],
)
@pytest.mark.parametrize(
    "name",
    [
        "data",
        "empty.data",
        "data.empty.data",
    ],
)
@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_non_apex_answer(name, zone, do, de):
    populated = name != "empty.data"
    signed = do and (zone != "unsigned")

    msg = isctest.query.create(f"{name}.{zone}", "txt", dnssec=do, deleg=de)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    if populated:
        isctest.check.rr_count_eq(res.answer, 2 if signed else 1)
        sig = [
            r
            for r in res.answer
            if str(r.name) == f"{name}.{zone}."
            and r.rdtype == rdatatype.RRSIG
            and r.covers == rdatatype.TXT
        ]
        assert (signed and sig) or (not signed and not sig)
    else:
        isctest.check.rr_count_eq(res.answer, 0)
        isctest.check.rr_count_eq(res.authority, 4 if signed else 1)


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "do, de",
    [
        [True, True],
        [True, False],
        [False, True],
        [False, False],
    ],
)
@pytest.mark.parametrize(
    "qtype",
    [
        61440,  # deleg is not yet defined by dnspython
        "nsec",
        "txt",
        "a",
    ],
)
@pytest.mark.parametrize(
    "name",
    [
        "nsonly",
        "delegonly",
        "mixed",
    ],
)
@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_zonecut_answers(name, zone, qtype, do, de):
    # which delegation type should we expect?
    has_ns = name in ("mixed", "nsonly")
    has_deleg = name in ("mixed", "delegonly")

    # answers without DO should be the same as unsigned
    signed = do and (zone != "unsigned")
    optout = do and (zone == "optout")

    # skip queries for NSEC or DELEG for zones and names that don't have them
    if qtype == "nsec" and zone != "nsec":
        return
    if qtype == 61440 and not has_deleg:
        return

    msg = isctest.query.create(f"{name}.{zone}", qtype, dnssec=do, deleg=de)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    # check that we get the EDE response for DELEG-only referrals if !DE
    if has_deleg and not has_ns and qtype != 61440 and qtype != "nsec":
        if not de:
            isctest.check.ede(res, 34)
        else:
            isctest.check.noede(res)

    # we don't treat deleg as an atparent type if the client is
    # deleg-unaware or there's an NS that can override it.
    atparent = qtype == "nsec" or (qtype == 61440 and (de or not has_ns))

    # check that DELEG is in the NSEC bitmap, if present
    if qtype == "nsec" and has_deleg:
        assert "TYPE61440" in str(res.answer[0])
    if qtype == "nsec" and not has_deleg:
        assert "TYPE61440" not in str(res.answer[0])

    expected_answer = 0
    expected_authority = 0

    if atparent:
        # the answer will be in the answer section,
        # no authority section needed
        expected_answer = 2 if signed else 1
    elif not signed:
        expected_authority = 1  # unsigned NS or DELEG
    elif has_ns:
        expected_authority = 3  # NS plus signed NSEC/NSEC3
        if has_deleg and de:
            expected_authority = 4  # signed DELEG, signed NSEC/NSEC3
        if optout:
            expected_authority += 2  # another signed NSEC3
    elif has_deleg:
        expected_authority = 4  # signed DELEG -or- SOA, and signed NSEC/NSEC3
    else:
        assert False, "impossible condition"

    isctest.check.rr_count_eq(res.answer, expected_answer)
    isctest.check.rr_count_eq(res.authority, expected_authority)

    # is this an NXRRSET?
    negative = res.authority and res.authority[0].rdtype == rdatatype.SOA

    if expected_answer or negative:
        isctest.check.aaflag(res)
    else:
        isctest.check.noaaflag(res)


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "do, de",
    [
        [True, True],
        [True, False],
        [False, True],
        [False, False],
    ],
)
@pytest.mark.parametrize(
    "qtype",
    [
        61440,  # deleg is not yet defined by dnspython
        "ds",
    ],
)
@pytest.mark.parametrize(
    "name",
    [
        "nsonly-ds",
        "delegonly-ds",
        "mixed-ds",
    ],
)
@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_secure_zonecut_answers(name, zone, qtype, do, de):
    has_deleg = name in ("mixed", "delegonly")
    signed = do and (zone != "unsigned")

    # skip queries for DELEG for names that don't have it
    if qtype == 61440 and not has_deleg:
        return

    msg = isctest.query.create(f"{name}.{zone}", qtype, dnssec=do, deleg=de)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    isctest.check.rr_count_eq(res.answer, 2 if signed else 1)
    isctest.check.rr_count_eq(res.authority, 0)


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "do, de",
    [
        [True, True],
        [True, False],
        [False, True],
        [False, False],
    ],
)
@pytest.mark.parametrize(
    "name",
    [
        "nsonly",
        "delegonly",
        "mixed",
    ],
)
@pytest.mark.parametrize(
    "zone",
    [
        "nsec",
        "nsec3",
        "optout",
        "unsigned",
    ],
)
def test_below_zonecut_answers(name, zone, do, de):
    # which delegation type should we expect?
    has_ns = name in ("mixed", "nsonly")
    has_deleg = name in ("mixed", "delegonly")

    # answers without DO should be the same as unsigned
    signed = do and (zone != "unsigned")
    optout = do and (zone == "optout")
    nsec3 = do and zone in ("optout", "nsec3")

    msg = isctest.query.create(f"foo.{name}.{zone}", "txt", dnssec=do, deleg=de)
    res = isctest.query.tcp(msg, "10.53.0.1")

    # all of these queries should return referrals except
    # delegonly, which should be an NXDOMAIN
    if has_deleg and not has_ns and not de:
        isctest.check.nxdomain(res)
    else:
        isctest.check.noerror(res)

    if not signed:
        # unsigned NS or DELEG
        expected = 1
    elif has_ns:
        # NS plus signed NSEC/NSEC3
        expected = 3
        if has_deleg and de:
            # signed DELEG, signed NSEC/NSEC3
            expected = 4
        if optout:
            # an extra signed NSEC3: wildcard
            expected += 2
    elif has_deleg and de:
        # signed DELEG and NSEC/NSEC3 -or- signed SOA and NSEC/NSEC3
        expected = 4
    elif has_deleg:
        # signed SOA and NSEC/NSEC3
        expected = 4
        if optout:
            # another signed NSEC3: wildcard
            expected += 2
        elif nsec3:
            # two more signed NSEC3s: encloser, wildcard
            expected += 4
    else:
        assert False, "impossible condition"
    isctest.check.rr_count_eq(res.authority, expected)


@pytest.mark.requires_zones_loaded("ns1")
@pytest.mark.parametrize(
    "do, de",
    [
        [True, True],
        [True, False],
        [False, True],
        [False, False],
    ],
)
@pytest.mark.parametrize(
    "qtype",
    [
        61440,  # deleg is not yet defined by dnspython
        "nsec",
        "txt",
        "a",
    ],
)
def test_deleg_updates(qtype, do, de):
    # convert nsonly to a mixed delegation
    up = update.UpdateMessage("nsec.")
    # pylint: disable=anomalous-backslash-in-string
    up.add("nsonly.nsec.", 300, 61440, "\# 8 000100040a350003")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)

    # wait for the update to complete
    for _ in range(10):
        msg = isctest.query.create("nsonly.nsec.", 61440, deleg=True)
        res = isctest.query.tcp(msg, "10.53.0.1")
        if len(res.answer) == 2:
            break
        time.sleep(1)

    msg = isctest.query.create("nsonly.nsec.", qtype, dnssec=do, deleg=de)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    atparent = qtype == "nsec" or (qtype == 61440 and de)

    # check that DELEG is in the NSEC bitmap, if present
    if qtype == "nsec":
        assert "TYPE61440" in str(res.answer[0])

    if atparent:
        isctest.check.rr_count_eq(res.answer, 2 if do else 1)
        expected = 0
    elif not do:
        expected = 1  # unsigned NS or DELEG
    else:
        expected = 3  # NS plus signed NSEC/NSEC3
        if de:
            expected = 4  # signed DELEG, signed NSEC/NSEC3
    isctest.check.rr_count_eq(res.authority, expected)
