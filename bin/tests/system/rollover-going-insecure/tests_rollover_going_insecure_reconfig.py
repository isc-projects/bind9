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

# pylint: disable=redefined-outer-name,unused-import

import pytest

import isctest
from rollover.common import (
    pytestmark,
    alg,
    size,
    CDSS,
    DEFAULT_CONFIG,
    DURATION,
    UNSIGNING_CONFIG,
)


@pytest.fixture(scope="module", autouse=True)
def reconfigure_policy(ns6, templates):
    templates.render("ns6/named.conf", {"policy": "insecure"})
    ns6.reconfigure()


@pytest.mark.parametrize(
    "zone",
    [
        "going-insecure.kasp",
        "going-insecure-dynamic.kasp",
    ],
)
def test_going_insecure_reconfig_step1(zone, alg, size, ns6):
    config = DEFAULT_CONFIG
    policy = "insecure"
    zone = f"step1.{zone}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    # Key goal states should be HIDDEN.
    # The DS may be removed if we are going insecure.
    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"ksk 0 {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:unretentive offset:{-DURATION['P10D']}",
            f"zsk {DURATION['P60D']} {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{-DURATION['P10D']}",
        ],
        # Next key event is when the DS becomes HIDDEN. This
        # happens after the# parent propagation delay plus DS TTL.
        "nextev": DEFAULT_CONFIG["ds-ttl"] + DEFAULT_CONFIG["parent-propagation-delay"],
        # Going insecure, check for CDS/CDNSKEY DELETE, and skip key timing checks.
        "cds-delete": True,
        "check-keytimes": False,
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)


@pytest.mark.parametrize(
    "zone",
    [
        "going-insecure.kasp",
        "going-insecure-dynamic.kasp",
    ],
)
def test_going_insecure_reconfig_step2(zone, alg, size, ns6):
    config = DEFAULT_CONFIG
    policy = "insecure"
    zone = f"step2.{zone}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    # The DS is long enough removed from the zone to be considered
    # HIDDEN.  This means the DNSKEY and the KSK signatures can be
    # removed.
    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"ksk 0 {alg} {size} goal:hidden dnskey:unretentive krrsig:unretentive ds:hidden offset:{-DURATION['P10D']}",
            f"zsk {DURATION['P60D']} {alg} {size} goal:hidden dnskey:unretentive zrrsig:unretentive offset:{-DURATION['P10D']}",
        ],
        # Next key event is when the DNSKEY becomes HIDDEN.
        # This happens after the propagation delay, plus DNSKEY TTL.
        "nextev": UNSIGNING_CONFIG["dnskey-ttl"]
        + DEFAULT_CONFIG["zone-propagation-delay"],
        # Zone is no longer signed.
        "zone-signed": False,
        "check-keytimes": False,
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
