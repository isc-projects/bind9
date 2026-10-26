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

from nsec_synthesis.common import (
    SIGNED_ZONE_MARKS,
    check_forged_nsec,
    get_nsec,
    has_a,
    make_key,
)

import isctest

F004_ZONE = "f004.test."
ATTACKER = f"attacker.{F004_ZONE}"
VICTIM = f"victim.{F004_ZONE}"
POISON_NEXT = f"b.{VICTIM}"
VICTIM_A = "203.0.113.1"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    keys = {F004_ZONE: make_key(F004_ZONE)}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    dnskey = "".join(keys[f"{F004_ZONE}"]["dnskey"].split()[3:])
    return {"DNSKEY": dnskey}


def test_pending_trust_nsec_cd_cache_poisoning():
    """
    Reproducer for #5872:
    F-004 Cache Poisoning via Pending-Trust NSEC in Aggressive Cache
    """
    # Step 1: Prime SOA parent (and DNSKEY as subquery)
    soa = isctest.query.tcp(isctest.query.create(F004_ZONE, "SOA"), RESOLVER)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Step 2: Inject Forged NSEC via CD=1 Query
    poison = isctest.query.tcp(
        isctest.query.create(ATTACKER, "NSEC", cd=True), RESOLVER
    )
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(poison, poison.answer, ATTACKER, POISON_NEXT, F004_ZONE, 9999)

    # Step 3: Exploit Against Victim Domain
    response = isctest.query.tcp(isctest.query.create(VICTIM, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert get_nsec(response, response.authority, ATTACKER) is None

    # Step 4: Exploit Against Stub Client
    response = isctest.query.tcp(
        isctest.query.create(VICTIM, "A", dnssec=False), RESOLVER
    )
    isctest.check.noerror(response)
    assert has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert get_nsec(response, response.authority, ATTACKER) is None

    # Step 5: Verify Upstream Queries
    with open("ans1/ans.run", "r", encoding="utf-8") as file:
        assert f"Received {VICTIM.rstrip('.')}/IN/A" in file.read()
