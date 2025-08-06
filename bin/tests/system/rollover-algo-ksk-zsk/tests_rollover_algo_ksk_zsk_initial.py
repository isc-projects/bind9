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

# pylint: disable=unused-import

import isctest
from rollover.common import (
    pytestmark,
    CDSS,
    DURATION,
    TIMEDELTA,
    ALGOROLL_CONFIG,
)


def test_algoroll_ksk_zsk_initial(ns6):
    config = ALGOROLL_CONFIG
    policy = "rsasha256"
    zone = "step1.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"ksk 0 8 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{-DURATION['P7D']}",
            f"zsk 0 8 2048 goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{-DURATION['P7D']}",
        ],
        "nextev": TIMEDELTA["PT1H"],
    }
    isctest.kasp.check_rollover_step(ns6, config, policy, step)
