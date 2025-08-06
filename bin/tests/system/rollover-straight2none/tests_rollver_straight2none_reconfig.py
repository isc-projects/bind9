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
    DEFAULT_CONFIG,
)


@pytest.fixture(scope="module", autouse=True)
def reconfigure_policy(ns6, templates):
    isctest.kasp.wait_keymgr_done(ns6, "going-straight-to-none.kasp")
    isctest.kasp.wait_keymgr_done(ns6, "going-straight-to-none-dynamic.kasp")

    templates.render("ns6/named.conf", {"policy": "none"})
    ns6.reconfigure()


@pytest.mark.parametrize(
    "zone",
    [
        "going-straight-to-none.kasp",
        "going-straight-to-none-dynamic.kasp",
    ],
)
def test_straight2none_reconfig(zone, ns6, alg, size):
    config = DEFAULT_CONFIG
    policy = None

    step = {
        "zone": zone,
        "cdss": CDSS,
        # These zones will go bogus after signatures expire, but
        # remain validly signed for now.
        "keyprops": [
            f"csk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{-DURATION['P10D']}",
        ],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
