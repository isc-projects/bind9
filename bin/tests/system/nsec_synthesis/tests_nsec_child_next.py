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

import pytest

from nsec_synthesis.common import (
    F023_ZONE,
    SIGNED_ZONE_MARKS,
    check_forged_nsec,
    get_nsec,
    has_a,
)

import isctest
import isctest.template
import isctest.zone

EVIL = f"evil.{F023_ZONE}"
POISON = f"0.{EVIL}"
POISON_NEXT = f"zzz.{F023_ZONE}"
TARGET = f"target.{F023_ZONE}"
TARGET_A = "192.0.2.77"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    evil = isctest.zone.Zone(EVIL, isctest.template.ANS4)
    zone = isctest.zone.Zone(F023_ZONE, isctest.template.ANS4, signed=True)
    zone.delegations = [evil]
    zone.configure(csk=True)
    return {"trust_anchors": zone.trust_anchors()}


def _prime_parent_for_aggressive_nsec(resolver):
    soa = isctest.query.tcp(isctest.query.create(F023_ZONE, "SOA"), resolver.ip)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    nsec = isctest.query.tcp(isctest.query.create(F023_ZONE, "NSEC"), resolver.ip)
    isctest.check.noerror(nsec)
    isctest.check.adflag(nsec)


@pytest.mark.asyncserver_test
def test_direct_insecure_child_nsec_next_fixture(ans4, f023_key_tags):
    poison = isctest.query.tcp(isctest.query.create(POISON, "NSEC"), ans4.ip)
    isctest.check.noerror(poison)
    isctest.check.aaflag(poison)
    check_forged_nsec(
        poison, poison.answer, POISON, POISON_NEXT, F023_ZONE, f023_key_tags
    )


def test_resolver_does_not_synth_from_insecure_child_nsec(ns2, f023_key_tags):
    _prime_parent_for_aggressive_nsec(ns2)

    poison = isctest.query.tcp(isctest.query.create(POISON, "NSEC"), ns2.ip)
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(
        poison, poison.answer, POISON, POISON_NEXT, F023_ZONE, f023_key_tags
    )

    response = isctest.query.tcp(isctest.query.create(TARGET, "A"), ns2.ip)
    isctest.check.noerror(response)
    assert has_a(response, TARGET, TARGET_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.authority, POISON)
