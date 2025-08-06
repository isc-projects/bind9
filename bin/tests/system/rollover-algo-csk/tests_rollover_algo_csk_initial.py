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

import isctest
from rollover.common import (
    pytestmark,
    CDSS,
    DURATION,
    TIMEDELTA,
    ALGOROLL_CONFIG,
)


def test_algoroll_csk_initial(ns6):
    config = ALGOROLL_CONFIG
    policy = "csk-algoroll"
    zone = "step1.csk-algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"csk 0 8 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{-DURATION['P7D']}",
        ],
        "nextev": TIMEDELTA["PT1H"],
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
