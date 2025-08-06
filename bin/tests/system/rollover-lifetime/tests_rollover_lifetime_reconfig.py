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
from isctest.util import param
from rollover.common import (
    pytestmark,
    alg,
    size,
    CDSS,
    DEFAULT_CONFIG,
    DURATION,
)


@pytest.fixture(scope="module", autouse=True)
def reconfigure_policy(ns6, templates):
    isctest.kasp.wait_keymgr_done(ns6, "shorter-lifetime")
    isctest.kasp.wait_keymgr_done(ns6, "longer-lifetime")
    isctest.kasp.wait_keymgr_done(ns6, "limit-lifetime")
    isctest.kasp.wait_keymgr_done(ns6, "unlimit-lifetime")

    templates.render("ns6/named.conf", {"change_lifetime": True})
    ns6.reconfigure()


@pytest.mark.parametrize(
    "zone, policy, lifetime",
    [
        param("shorter-lifetime", "short-lifetime", "P6M"),
        param("longer-lifetime", "long-lifetime", "P1Y"),
        param(
            "limit-lifetime",
            "short-lifetime",
            "P6M",
        ),
        param("unlimit-lifetime", "unlimited-lifetime", 0),
    ],
)
def test_lifetime_reconfig(zone, policy, lifetime, alg, size, ns6):
    config = DEFAULT_CONFIG

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"csk {DURATION[lifetime]} {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
        ],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
