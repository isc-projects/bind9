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
    DURATION,
    UNSIGNING_CONFIG,
)


@pytest.mark.parametrize(
    "zone",
    [
        "going-insecure.kasp",
        "going-insecure-dynamic.kasp",
    ],
)
def test_going_insecure_initial(zone, ns6, alg, size):
    config = UNSIGNING_CONFIG
    policy = "unsigning"
    zone = f"step1.{zone}"

    isctest.kasp.wait_keymgr_done(ns6, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{-DURATION['P10D']}",
            f"zsk {DURATION['P60D']} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{-DURATION['P10D']}",
        ],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
