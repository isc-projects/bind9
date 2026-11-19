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

POISON_NEXT = f"z.{F004_ZONE}"

pytestmark = SIGNED_ZONE_MARKS


def bootstrap():
    return f004_bootstrap()


def test_pending_exact_nodata_nsec_cache_poisoning(ns2, f004_key_tags):
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
    soa = isctest.query.tcp(isctest.query.create(F004_ZONE, "SOA"), ns2.ip)
    isctest.check.noerror(soa)
    isctest.check.adflag(soa)

    # Inject a forged NSEC owned by the victim name via a CD=1 query; it is
    # cached at pending trust on the victim node.
    poison = isctest.query.tcp(
        isctest.query.create(F004_VICTIM, "NSEC", cd=True), ns2.ip
    )
    isctest.check.noerror(poison)
    isctest.check.noadflag(poison)
    check_forged_nsec(
        poison, poison.answer, F004_VICTIM, POISON_NEXT, F004_ZONE, f004_key_tags
    )

    # Query the victim's A record. The pending NSEC must not be used to
    # synthesize a NODATA; the resolver fetches and validates the real A.
    response = isctest.query.tcp(isctest.query.create(F004_VICTIM, "A"), ns2.ip)
    isctest.check.noerror(response)
    assert has_a(response, F004_VICTIM, F004_VICTIM_A), response.to_text()
    isctest.check.adflag(response)
    assert not get_nsec(response, response.answer, F004_VICTIM)
    assert not get_nsec(response, response.authority, F004_VICTIM)
