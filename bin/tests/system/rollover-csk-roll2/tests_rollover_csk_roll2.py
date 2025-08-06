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


CDSS = ["CDNSKEY", "CDS (SHA-256)", "CDS (SHA-384)"]
CONFIG = {
    "dnskey-ttl": TIMEDELTA["PT1H"],
    "ds-ttl": TIMEDELTA["PT1H"],
    "max-zone-ttl": TIMEDELTA["P1D"],
    "parent-propagation-delay": TIMEDELTA["P7D"],
    "publish-safety": TIMEDELTA["PT1H"],
    "purge-keys": TIMEDELTA[0],
    "retire-safety": TIMEDELTA["PT1H"],
    "signatures-refresh": TIMEDELTA["PT12H"],
    "signatures-validity": TIMEDELTA["P1D"],
    "zone-propagation-delay": TIMEDELTA["PT1H"],
}
POLICY = "csk-roll2"
CSK_LIFETIME = timedelta(days=31 * 6)
LIFETIME_POLICY = int(CSK_LIFETIME.total_seconds())

IPUB = Ipub(CONFIG)
IRET = Iret(CONFIG, zsk=True, ksk=True)
IRETZSK = Iret(CONFIG)
IRETKSK = Iret(CONFIG, ksk=True)
KEYTTLPROP = CONFIG["dnskey-ttl"] + CONFIG["zone-propagation-delay"]
OFFSETS = {}
OFFSETS["step1-p"] = -int(timedelta(days=7).total_seconds())
OFFSETS["step2-p"] = -int(CSK_LIFETIME.total_seconds() - IPUB.total_seconds())
OFFSETS["step2-s"] = 0
OFFSETS["step3-p"] = -int(CSK_LIFETIME.total_seconds())
OFFSETS["step3-s"] = -int(IPUB.total_seconds())
OFFSETS["step4-p"] = OFFSETS["step3-p"] - int(IRETZSK.total_seconds())
OFFSETS["step4-s"] = OFFSETS["step3-s"] - int(IRETZSK.total_seconds())
OFFSETS["step5-p"] = OFFSETS["step4-p"] - int(
    IRETKSK.total_seconds() - IRETZSK.total_seconds()
)
OFFSETS["step5-s"] = OFFSETS["step4-s"] - int(
    IRETKSK.total_seconds() - IRETZSK.total_seconds()
)
OFFSETS["step6-p"] = OFFSETS["step5-p"] - int(KEYTTLPROP.total_seconds())
OFFSETS["step6-s"] = OFFSETS["step5-s"] - int(KEYTTLPROP.total_seconds())
OFFSETS["step7-p"] = OFFSETS["step6-p"] - int(timedelta(days=90).total_seconds())
OFFSETS["step7-s"] = OFFSETS["step6-s"] - int(timedelta(days=90).total_seconds())


def test_csk_roll2_step1(alg, size, ns3):
    zone = "step1.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Introduce the first key. This will immediately be active.
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step1-p']}",
        ],
        # Next key event is when the successor CSK needs to be published
        # minus time already elapsed. This is Lcsk - Ipub + Dreg (we ignore
        # registration delay).
        "nextev": CSK_LIFETIME - IPUB - TIMEDELTA["P7D"],
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step2(alg, size, ns3):
    zone = "step2.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Successor CSK is prepublished (signs DNSKEY RRset, but not yet
        # other RRsets).
        # CSK1 goal: omnipresent -> hidden
        # CSK2 goal: hidden -> omnipresent
        # CSK2 dnskey: hidden -> rumoured
        # CSK2 krrsig: hidden -> rumoured
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step2-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:hidden ds:hidden offset:{OFFSETS['step2-s']}",
        ],
        "keyrelationships": [0, 1],
        # Next key event is when the successor CSK becomes OMNIPRESENT.
        "nextev": IPUB,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step3(alg, size, ns3):
    zone = "step3.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Successor CSK becomes omnipresent, meaning we can start signing
        # the remainder of the zone with the successor CSK, and we can
        # submit the DS.
        "zone": zone,
        "cdss": CDSS,
        # Predecessor CSK will be removed, so moving to UNRETENTIVE.
        # CSK1 zrrsig: omnipresent -> unretentive
        # Successor CSK DNSKEY is OMNIPRESENT, so moving ZRRSIG to RUMOURED.
        # CSK2 dnskey: rumoured -> omnipresent
        # CSK2 krrsig: rumoured -> omnipresent
        # CSK2 zrrsig: hidden -> rumoured
        # The predecessor DS can be withdrawn and the successor DS can be
        # introduced.
        # CSK1 ds: omnipresent -> unretentive
        # CSK2 ds: hidden -> rumoured
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent zrrsig:unretentive ds:unretentive offset:{OFFSETS['step3-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:rumoured ds:rumoured offset:{OFFSETS['step3-s']}",
        ],
        "keyrelationships": [0, 1],
        # Next key event is when the predecessor DS has been replaced with
        # the successor DS and enough time has passed such that the all
        # validators that have this DS RRset cached only know about the
        # successor DS.  This is the the retire interval.
        "nextev": IRETZSK,
        # Set 'smooth' to true so expected signatures of subdomain are
        # from the predecessor ZSK.
        "smooth": True,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step4(alg, size, ns3):
    zone = "step4.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # The predecessor ZRRSIG is HIDDEN. The successor ZRRSIG is
        # OMNIPRESENT.
        # CSK1 zrrsig: unretentive -> hidden
        # CSK2 zrrsig: rumoured -> omnipresent
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent zrrsig:hidden ds:unretentive offset:{OFFSETS['step4-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:rumoured offset:{OFFSETS['step4-s']}",
        ],
        "keyrelationships": [0, 1],
        # Next key event is when the predecessor DS has been replaced with
        # the successor DS and enough time has passed such that the all
        # validators that have this DS RRset cached only know about the
        # successor DS. This is the retire interval of the KSK part (minus)
        # time already elapsed).
        "nextev": IRET - IRETZSK,
        # We already swapped the DS in the previous step, so disable ds-swap.
        "ds-swap": False,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step5(alg, size, ns3):
    zone = "step5.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # The predecessor DNSKEY can be removed.
        # CSK1 dnskey: omnipresent -> unretentive
        # CSK1 krrsig: omnipresent -> unretentive
        # CSK1 ds: unretentive -> hidden
        # The successor key is now fully OMNIPRESENT.
        # CSK2 ds: rumoured -> omnipresent
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:unretentive krrsig:unretentive zrrsig:hidden ds:hidden offset:{OFFSETS['step5-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step5-s']}",
        ],
        "keyrelationships": [0, 1],
        # Next key event is when the DNSKEY enters the HIDDEN state.
        # This is the DNSKEY TTL plus zone propagation delay.
        "nextev": KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step6(alg, size, ns3):
    zone = "step6.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # The predecessor CSK is now completely HIDDEN.
        # CSK1 dnskey: unretentive -> hidden
        # CSK1 krrsig: unretentive -> hidden
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:hidden krrsig:hidden zrrsig:hidden ds:hidden offset:{OFFSETS['step6-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step6-s']}",
        ],
        "keyrelationships": [0, 1],
        # Next key event is when the new successor needs to be published.
        # This is the Lcsk, minus time passed since the key was published.
        "nextev": CSK_LIFETIME - IRET - IPUB - KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)


def test_csk_roll2_step7(alg, size, ns3):
    zone = "step7.csk-roll2.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        "zone": zone,
        "cdss": CDSS,
        # The predecessor CSK is now completely HIDDEN.
        "keyprops": [
            f"csk {LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:hidden krrsig:hidden zrrsig:hidden ds:hidden offset:{OFFSETS['step7-p']}",
            f"csk {LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{OFFSETS['step7-s']}",
        ],
        "keyrelationships": [0, 1],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns3, CONFIG, POLICY, step)
