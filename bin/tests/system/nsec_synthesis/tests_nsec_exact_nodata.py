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

from isctest.template import TrustAnchor
from nsec_synthesis.common import (
    SIGNED_ZONE_MARKS,
    check_forged_nsec,
    get_nsec,
    has_a,
    make_key,
)

import isctest

F004_ZONE = "f004.test."
VICTIM = f"victim.{F004_ZONE}"
POISON_NEXT = f"z.{F004_ZONE}"
VICTIM_A = "203.0.113.1"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    keys = {F004_ZONE: make_key(F004_ZONE)}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    dnskey = keys[F004_ZONE]["dnskey"].split()
    contents = f'{" ".join(dnskey[:3])} "{"".join(dnskey[3:])}"'
    return {"trust_anchors": [TrustAnchor(F004_ZONE, "static-key", contents)]}


def test_pending_exact_nodata_nsec_cache_poisoning():
    """
    Companion to #5872 that covers the query_coveringnsec() trust check on
    the exact-match NODATA branch (the `if (exists)` path in ns/query.c),
    rather than the covering-NSEC path gated in qpcache.c find_coveringnsec().

    An NSEC owned by the victim name itself, injected at pending trust via a
    CD=1 query, is returned by the cache as a NODATA proof for the exact node.
    It must not be used to synthesize a NODATA answer that would deny the
    victim's real A record.
    """
    # Prime the zone SOA (and the DNSKEY as a subquery) at secure trust.
    soa = isctest.query.tcp(isctest.query.create(F004_ZONE, "SOA"), RESOLVER)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Inject a forged NSEC owned by the victim name via a CD=1 query; it is
    # cached at pending trust on the victim node.
    poison = isctest.query.tcp(isctest.query.create(VICTIM, "NSEC", cd=True), RESOLVER)
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(poison, poison.answer, VICTIM, POISON_NEXT, F004_ZONE, 9999)

    # Query the victim's A record. The pending NSEC must not be used to
    # synthesize a NODATA; the resolver fetches and validates the real A.
    response = isctest.query.tcp(isctest.query.create(VICTIM, "A"), RESOLVER)
    isctest.check.noerror(response)
    assert has_a(response, VICTIM, VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.answer, VICTIM)
    assert not get_nsec(response, response.authority, VICTIM)
