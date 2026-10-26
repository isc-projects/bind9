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

from pathlib import Path

import json

import dns.flags

from nsec_synthesis.common import (
    SIGNED_ZONE_MARKS,
    check_forged_nsec,
    get_nsec,
    has_a,
    make_key,
)

import isctest

F023_ZONE = "f023.test."
EVIL = f"evil.{F023_ZONE}"
POISON = f"0.{EVIL}"
POISON_NEXT = f"zzz.{F023_ZONE}"
TARGET = f"target.{F023_ZONE}"
TARGET_A = "192.0.2.77"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    keys = {F023_ZONE: make_key(F023_ZONE)}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    dnskey = "".join(keys[F023_ZONE]["dnskey"].split()[3:])
    return {"DNSKEY": dnskey}


def _prime_parent_for_aggressive_nsec():
    soa = isctest.query.tcp(isctest.query.create(F023_ZONE, "SOA"), RESOLVER)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    nsec = isctest.query.tcp(isctest.query.create(F023_ZONE, "NSEC"), RESOLVER)
    isctest.check.noerror(nsec)
    isctest.check.adflag(nsec)


def test_direct_insecure_child_nsec_next_fixture():
    poison = isctest.query.tcp(isctest.query.create(POISON, "NSEC"), AUTH)
    isctest.check.noerror(poison)
    assert poison.flags & dns.flags.AA
    check_forged_nsec(poison, poison.answer, POISON, POISON_NEXT, F023_ZONE, 12345)


def test_resolver_does_not_synth_from_insecure_child_nsec():
    _prime_parent_for_aggressive_nsec()

    poison = isctest.query.tcp(isctest.query.create(POISON, "NSEC"), RESOLVER)
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(poison, poison.answer, POISON, POISON_NEXT, F023_ZONE, 12345)

    response = isctest.query.tcp(isctest.query.create(TARGET, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert has_a(response, TARGET, TARGET_A), response.to_text()
    isctest.check.adflag(response)
    assert get_nsec(response, response.authority, POISON) is None
