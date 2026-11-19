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

from nsec_synthesis.common import (
    F004_VICTIM,
    F004_VICTIM_A,
    F004_ZONE,
    SIGNED_ZONE_MARKS,
    check_forged_nsec,
    f004_bootstrap,
    get_nsec,
    has_a,
)

import isctest

ATTACKER = f"attacker.{F004_ZONE}"
POISON_NEXT = f"b.{F004_VICTIM}"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    return f004_bootstrap()


def test_pending_trust_nsec_cd_cache_poisoning(ns2, ans1, f004_key_tags):
    """
    Reproducer for #5872:
    F-004 Cache Poisoning via Pending-Trust NSEC in Aggressive Cache
    """
    # Step 1: Prime SOA parent (and DNSKEY as subquery)
    soa = isctest.query.tcp(isctest.query.create(F004_ZONE, "SOA"), ns2.ip)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Step 2: Inject Forged NSEC via CD=1 Query
    poison = isctest.query.tcp(isctest.query.create(ATTACKER, "NSEC", cd=True), ns2.ip)
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(
        poison, poison.answer, ATTACKER, POISON_NEXT, F004_ZONE, f004_key_tags
    )

    # Step 3: Exploit Against Victim Domain
    response = isctest.query.tcp(isctest.query.create(F004_VICTIM, "A"), ns2.ip)
    isctest.check.noerror(response)
    assert has_a(response, F004_VICTIM, F004_VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.authority, ATTACKER)

    # Step 4: Exploit Against Stub Client
    response = isctest.query.tcp(
        isctest.query.create(F004_VICTIM, "A", dnssec=False), ns2.ip
    )
    isctest.check.noerror(response)
    assert has_a(response, F004_VICTIM, F004_VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.authority, ATTACKER)

    # Step 5: Verify Upstream Queries
    assert f"Received {F004_VICTIM.rstrip('.')}/IN/A" in ans1.log
