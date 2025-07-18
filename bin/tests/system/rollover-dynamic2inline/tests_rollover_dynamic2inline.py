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
from common import (
    pytestmark,
    alg,
    size,
    CDSS,
    DEFAULT_CONFIG,
)


def test_dynamic2inline(alg, size, servers, templates):
    config = DEFAULT_CONFIG
    policy = "default"

    step = {
        "zone": "dynamic2inline.kasp",
        "cdss": CDSS,
        "keyprops": [
            f"csk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
        ],
        "nextev": None,
    }

    isctest.kasp.check_rollover_step(servers["ns6"], config, policy, step)

    templates.render("ns6/named.conf", {"change_lifetime": True})
    servers["ns6"].reconfigure()

    isctest.kasp.check_rollover_step(servers["ns6"], config, policy, step)
