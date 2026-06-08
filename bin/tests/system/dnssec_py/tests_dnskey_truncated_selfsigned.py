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

from re import compile as Re

from dnssec_py.common import DNSSEC_PY_MARK
from isctest.template import NS2, TrustAnchor, zones
from isctest.zone import Zone, configure_root

import isctest

pytestmark = DNSSEC_PY_MARK


def bootstrap():
    zone = Zone("truncated.selfsigned", NS2, signed=True)

    root = configure_root([zone], signed=False)  # just delegation, TA is added directly

    # The trust anchor key tag must match the revoked truncated self-signed key
    # in the zone (key tag 33167). The flags differ here (257 vs 385) because
    # the revoked bit is not part of the trust anchor, but it is part of the key
    # tag calculation.
    zone_ta = TrustAnchor("truncated.selfsigned", "static-key", '257 3 14 "fYA="')

    return {
        "trust_anchors": [zone_ta],
        "zones": zones([root, zone]),
    }


def test_truncated_dnskey(ns9):
    msg = isctest.query.create("a.truncated.selfsigned.", "A")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_line(Re("a.truncated.selfsigned/A.*broken trust chain"))
    isctest.check.servfail(res)
