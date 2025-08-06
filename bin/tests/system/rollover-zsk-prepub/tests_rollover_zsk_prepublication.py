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

from datetime import timedelta

import isctest
from isctest.kasp import Ipub, Iret
from rollover.common import (
    pytestmark,
    alg,
    size,
    TIMEDELTA,
)

CONFIG = {
    "dnskey-ttl": TIMEDELTA["PT1H"],
    "ds-ttl": TIMEDELTA["P1D"],
    "max-zone-ttl": TIMEDELTA["P1D"],
    "parent-propagation-delay": TIMEDELTA["PT1H"],
    "publish-safety": TIMEDELTA["P1D"],
    "purge-keys": TIMEDELTA["PT1H"],
    "retire-safety": TIMEDELTA["P2D"],
    "signatures-refresh": TIMEDELTA["P7D"],
    "signatures-validity": TIMEDELTA["P14D"],
    "zone-propagation-delay": TIMEDELTA["PT1H"],
}
POLICY = "zsk-prepub"
ZSK_LIFETIME = TIMEDELTA["P30D"]
LIFETIME_POLICY = int(ZSK_LIFETIME.total_seconds())
IPUB = Ipub(CONFIG)
IRET = Iret(CONFIG, rollover=True)
KEYTTLPROP = CONFIG["dnskey-ttl"] + CONFIG["zone-propagation-delay"]
OFFSETS = {}
OFFSETS["step1-p"] = -int(TIMEDELTA["P7D"].total_seconds())
OFFSETS["step2-p"] = -int(ZSK_LIFETIME.total_seconds() - IPUB.total_seconds())
OFFSETS["step2-s"] = 0
OFFSETS["step3-p"] = -int(ZSK_LIFETIME.total_seconds())
OFFSETS["step3-s"] = -int(IPUB.total_seconds())
OFFSETS["step4-p"] = OFFSETS["step3-p"] - int(IRET.total_seconds())
OFFSETS["step4-s"] = OFFSETS["step3-s"] - int(IRET.total_seconds())
OFFSETS["step5-p"] = OFFSETS["step4-p"] - int(KEYTTLPROP.total_seconds())
OFFSETS["step5-s"] = OFFSETS["step4-s"] - int(KEYTTLPROP.total_seconds())
OFFSETS["step6-p"] = OFFSETS["step5-p"] - int(CONFIG["purge-keys"].total_seconds())
OFFSETS["step6-s"] = OFFSETS["step5-s"] - int(CONFIG["purge-keys"].total_seconds())


def test_zsk_prepub_step1(alg, size, ns3):
    zone = "step1.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Introduce the first key. This will immediately be active.
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step1-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step1-p']}",
        ],
        # Next key event is when the successor ZSK needs to be published.
        # That is the ZSK lifetime - prepublication time (minus time
        # already passed).
        "nextev": ZSK_LIFETIME - IPUB - timedelta(days=7),
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_zsk_prepub_step2(alg, size, ns3):
    zone = "step2.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # it is time to pre-publish the successor zsk.
        # zsk1 goal: omnipresent -> hidden
        # zsk2 goal: hidden -> omnipresent
        # zsk2 dnskey: hidden -> rumoured
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step2-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step2-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:hidden offset:{OFFSETS['step2-s']}",
        ],
        "keyrelationships": [1, 2],
        # next key event is when the successor zsk becomes omnipresent.
        # that is the dnskey ttl plus the zone propagation delay
        "nextev": IPUB,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_zsk_prepub_step3(alg, size, ns3):
    zone = "step3.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # predecessor zsk is no longer actively signing. successor zsk is
        # now actively signing.
        # zsk1 zrrsig: omnipresent -> unretentive
        # zsk2 dnskey: rumoured -> omnipresent
        # zsk2 zrrsig: hidden -> rumoured
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step3-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent zrrsig:unretentive offset:{OFFSETS['step3-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:rumoured offset:{OFFSETS['step3-s']}",
        ],
        "keyrelationships": [1, 2],
        # next key event is when all the rrsig records have been replaced
        # with signatures of the new zsk, in other words when zrrsig
        # becomes omnipresent.
        "nextev": IRET,
        # set 'smooth' to true so expected signatures of subdomain are
        # from the predecessor zsk.
        "smooth": True,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_zsk_prepub_step4(alg, size, ns3):
    zone = "step4.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # predecessor zsk is no longer needed. all rrsets are signed with
        # the successor zsk.
        # zsk1 dnskey: omnipresent -> unretentive
        # zsk1 zrrsig: unretentive -> hidden
        # zsk2 zrrsig: rumoured -> omnipresent
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step4-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:unretentive zrrsig:hidden offset:{OFFSETS['step4-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step4-s']}",
        ],
        "keyrelationships": [1, 2],
        # next key event is when the dnskey enters the hidden state.
        # this is the dnskey ttl plus zone propagation delay.
        "nextev": KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_zsk_prepub_step5(alg, size, ns3):
    zone = "step5.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # predecessor zsk is now removed.
        # zsk1 dnskey: unretentive -> hidden
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step5-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:hidden zrrsig:hidden offset:{OFFSETS['step5-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step5-s']}",
        ],
        "keyrelationships": [1, 2],
        # next key event is when the new successor needs to be published.
        # this is the zsk lifetime minus IRET minus IPUB minus time
        # elapsed.
        "nextev": ZSK_LIFETIME - IRET - IPUB - KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_zsk_prepub_step6(alg, size, ns3):
    zone = "step6.zsk-prepub.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # predecessor zsk is now purged.
        "zone": zone,
        "keyprops": [
            f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step6-p']}",
            f"zsk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step6-s']}",
        ],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)
