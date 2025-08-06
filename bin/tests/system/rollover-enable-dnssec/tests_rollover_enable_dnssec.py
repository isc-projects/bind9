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
from isctest.kasp import Ipub, IpubC, Iret
from rollover.common import (
    pytestmark,
    alg,
    size,
    CDSS,
    TIMEDELTA,
)

CONFIG = {
    "dnskey-ttl": TIMEDELTA["PT5M"],
    "ds-ttl": TIMEDELTA["PT2H"],
    "max-zone-ttl": TIMEDELTA["PT12H"],
    "parent-propagation-delay": TIMEDELTA["PT1H"],
    "publish-safety": TIMEDELTA["PT5M"],
    "retire-safety": TIMEDELTA["PT20M"],
    "signatures-refresh": TIMEDELTA["P7D"],
    "signatures-validity": TIMEDELTA["P14D"],
    "zone-propagation-delay": TIMEDELTA["PT5M"],
}
POLICY = "enable-dnssec"
IPUB = Ipub(CONFIG)
IPUBC = IpubC(CONFIG, rollover=False)
IRETZSK = Iret(CONFIG, rollover=False)
IRETKSK = Iret(CONFIG, zsk=False, ksk=True, rollover=False)
OFFSETS = {}
OFFSETS["step1"] = 0
OFFSETS["step2"] = -int(IPUB.total_seconds())
OFFSETS["step3"] = -int(IRETZSK.total_seconds())
OFFSETS["step4"] = -int(IPUBC.total_seconds() + IRETKSK.total_seconds())


def test_rollover_enable_dnssec_step1(alg, size, ns3):
    zone = "step1.enable-dnssec.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"csk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden offset:{OFFSETS['step1']}",
        ],
        # Next key event is when the DNSKEY RRset becomes OMNIPRESENT,
        # after the publication interval.
        "nextev": IPUB,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_rollover_enable_dnssec_step2(alg, size, ns3):
    zone = "step2.enable-dnssec.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # The DNSKEY is omnipresent, but the zone signatures not yet.
        # Thus, the DS remains hidden.
        # dnskey: rumoured -> omnipresent
        # krrsig: rumoured -> omnipresent
        "keyprops": [
            f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:rumoured ds:hidden offset:{OFFSETS['step2']}",
        ],
        # Next key event is when the zone signatures become OMNIPRESENT,
        # Minus the time already elapsed.
        "nextev": IRETZSK - IPUB,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_rollover_enable_dnssec_step3(alg, size, ns3):
    zone = "step3.enable-dnssec.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # All signatures should be omnipresent, so the DS can be submitted.
        # zrrsig: rumoured -> omnipresent
        # ds: hidden -> rumoured
        "keyprops": [
            f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:rumoured offset:{OFFSETS['step3']}",
        ],
        # Next key event is when the DS can move to the OMNIPRESENT state.
        # This is after the retire interval.
        "nextev": IRETKSK,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_rollover_enable_dnssec_step4(alg, size, ns3):
    zone = "step4.enable-dnssec.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # DS has been published long enough.
        # ds: rumoured -> omnipresent
        "keyprops": [
            f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step4']}",
        ],
        # Next key event is never, the zone dnssec-policy has been
        # established. So we fall back to the default loadkeys interval.
        "nextev": TIMEDELTA["PT1H"],
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)
