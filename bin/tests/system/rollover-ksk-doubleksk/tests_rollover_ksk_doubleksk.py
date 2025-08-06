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
from rollover.common import (
    pytestmark,
    alg,
    size,
    KSK_CONFIG,
    KSK_LIFETIME,
    KSK_LIFETIME_POLICY,
    KSK_IPUB,
    KSK_IPUBC,
    KSK_IRET,
    KSK_KEYTTLPROP,
    TIMEDELTA,
)


CDSS = ["CDS (SHA-256)"]
POLICY = "ksk-doubleksk"
OFFSETS = {}
OFFSETS["step1-p"] = -int(TIMEDELTA["P7D"].total_seconds())
OFFSETS["step2-p"] = -int(KSK_LIFETIME.total_seconds() - KSK_IPUBC.total_seconds())
OFFSETS["step2-s"] = 0
OFFSETS["step3-p"] = -int(KSK_LIFETIME.total_seconds())
OFFSETS["step3-s"] = -int(KSK_IPUBC.total_seconds())
OFFSETS["step4-p"] = OFFSETS["step3-p"] - int(KSK_IRET.total_seconds())
OFFSETS["step4-s"] = OFFSETS["step3-s"] - int(KSK_IRET.total_seconds())
OFFSETS["step5-p"] = OFFSETS["step4-p"] - int(KSK_KEYTTLPROP.total_seconds())
OFFSETS["step5-s"] = OFFSETS["step4-s"] - int(KSK_KEYTTLPROP.total_seconds())
OFFSETS["step6-p"] = OFFSETS["step5-p"] - int(KSK_CONFIG["purge-keys"].total_seconds())
OFFSETS["step6-s"] = OFFSETS["step5-s"] - int(KSK_CONFIG["purge-keys"].total_seconds())


def test_ksk_doubleksk_step1(alg, size, ns3):
    zone = "step1.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Introduce the first key. This will immediately be active.
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step1-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step1-p']}",
        ],
        # Next key event is when the successor KSK needs to be published.
        # That is the KSK lifetime - prepublication time (minus time
        # already passed).
        "nextev": KSK_LIFETIME - KSK_IPUB - timedelta(days=7),
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)


def test_ksk_doubleksk_step2(alg, size, ns3):
    zone = "step2.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Successor KSK is prepublished (and signs DNSKEY RRset).
        # KSK1 goal: omnipresent -> hidden
        # KSK2 goal: hidden -> omnipresent
        # KSK2 dnskey: hidden -> rumoured
        # KSK2 krrsig: hidden -> rumoured
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step2-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step2-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden offset:{OFFSETS['step2-s']}",
        ],
        "keyrelationships": [1, 2],
        # Next key event is when the successor KSK becomes OMNIPRESENT.
        "nextev": KSK_IPUB,
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)


def test_ksk_doubleksk_step3(alg, size, ns3):
    zone = "step3.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # The successor DNSKEY RRset has become omnipresent.  The
        # predecessor DS  can be withdrawn and the successor DS can be
        # introduced.
        # KSK1 ds: omnipresent -> unretentive
        # KSK2 dnskey: rumoured -> omnipresent
        # KSK2 krrsig: rumoured -> omnipresent
        # KSK2 ds: hidden -> rumoured
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step3-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:unretentive offset:{OFFSETS['step3-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:rumoured offset:{OFFSETS['step3-s']}",
        ],
        "keyrelationships": [1, 2],
        # Next key event is when the predecessor DS has been replaced with
        # the successor DS and enough time has passed such that the all
        # validators that have this DS RRset cached only know about the
        # successor DS.  This is the the retire interval.
        "nextev": KSK_IRET,
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)


def test_ksk_doubleksk_step4(alg, size, ns3):
    zone = "step4.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # The predecessor DNSKEY may be removed, the successor DS is
        # omnipresent.
        # KSK1 dnskey: omnipresent -> unretentive
        # KSK1 krrsig: omnipresent -> unretentive
        # KSK1 ds: unretentive -> hidden
        # KSK2 ds: rumoured -> omnipresent
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step4-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:unretentive krrsig:unretentive ds:hidden offset:{OFFSETS['step4-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step4-s']}",
        ],
        "keyrelationships": [1, 2],
        # Next key event is when the DNSKEY enters the HIDDEN state.
        # This is the DNSKEY TTL plus zone propagation delay.
        "nextev": KSK_KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)


def test_ksk_doubleksk_step5(alg, size, ns3):
    zone = "step5.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # The predecessor DNSKEY is long enough removed from the zone it
        # has become hidden.
        # KSK1 dnskey: unretentive -> hidden
        # KSK1 krrsig: unretentive -> hidden
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step5-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:hidden dnskey:hidden krrsig:hidden ds:hidden offset:{OFFSETS['step5-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step5-s']}",
        ],
        "keyrelationships": [1, 2],
        # Next key event is when the new successor needs to be published.
        # This is the KSK lifetime minus Ipub minus Iret minus time elapsed.
        "nextev": KSK_LIFETIME - KSK_IPUB - KSK_IRET - KSK_KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)


def test_ksk_doubleksk_step6(alg, size, ns3):
    zone = "step6.ksk-doubleksk.autosign"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    step = {
        # Predecessor KSK is now purged.
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{OFFSETS['step6-p']}",
            f"ksk {KSK_LIFETIME_POLICY} {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{OFFSETS['step6-s']}",
        ],
        "nextev": None,
    }
    isctest.kasp.check_rollover_step(ns3, KSK_CONFIG, POLICY, step)
