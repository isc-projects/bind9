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
from isctest.kasp import KeyTimingMetadata
from rollover.common import (
    pytestmark,
    alg,
    size,
    CDSS,
    ALGOROLL_CONFIG,
    ALGOROLL_IPUB,
    ALGOROLL_IPUBC,
    ALGOROLL_IRET,
    ALGOROLL_IRETKSK,
    ALGOROLL_KEYTTLPROP,
    ALGOROLL_OFFSETS,
    ALGOROLL_OFFVAL,
    TIMEDELTA,
)

CONFIG = ALGOROLL_CONFIG
POLICY = "ecdsa256"
TIME_PASSED = 0  # set in reconfigure() fixture


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns6, templates):
    global TIME_PASSED  # pylint: disable=global-statement

    isctest.kasp.wait_keymgr_done(ns6, "step1.algorithm-roll.kasp")

    templates.render("ns6/named.conf", {"alg_roll": True})
    start_time = KeyTimingMetadata.now()
    ns6.reconfigure()

    # Calculate time passed to correctly check for next key events.
    TIME_PASSED = KeyTimingMetadata.now().value - start_time.value


def test_algoroll_ksk_zsk_reconfig_step1(ns6, alg, size):
    zone = "step1.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The RSASHA keys are outroducing.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            # The ECDSAP256SHA256 keys are introducing.
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:rumoured",
        ],
        # Next key event is when the ecdsa256 keys have been propagated.
        "nextev": ALGOROLL_IPUB,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)


def test_algoroll_ksk_zsk_reconfig_step2(ns6, alg, size):
    zone = "step2.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The RSASHA keys are outroducing, but need to stay present
            # until the new algorithm chain of trust has been established.
            # Thus the expected key states of these keys stay the same.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            # The ECDSAP256SHA256 keys are introducing. The DNSKEY RRset is
            # omnipresent, but the zone signatures are not.
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:hidden offset:{ALGOROLL_OFFSETS['step2']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:rumoured offset:{ALGOROLL_OFFSETS['step2']}",
        ],
        # Next key event is when all zone signatures are signed with the new
        # algorithm.  This is the max-zone-ttl plus zone propagation delay.  But
        # the publication interval has already passed. Also, prevent intermittent
        # false positives on slow platforms by subtracting the time passed between
        # key creation and invoking 'rndc reconfig'.
        "nextev": ALGOROLL_IPUBC - ALGOROLL_IPUB - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)


def test_algoroll_ksk_zsk_reconfig_step3(ns6, alg, size):
    zone = "step3.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The DS can be swapped.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:unretentive offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:rumoured offset:{ALGOROLL_OFFSETS['step3']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step3']}",
        ],
        # Next key event is when the DS becomes OMNIPRESENT. This happens
        # after the retire interval.
        "nextev": ALGOROLL_IRETKSK - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)


def test_algoroll_ksk_zsk_reconfig_step4(ns6, alg, size):
    zone = "step4.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The old DS is HIDDEN, we can remove the old algorithm records.
            f"ksk 0 8 2048 goal:hidden dnskey:unretentive krrsig:unretentive ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:unretentive zrrsig:unretentive offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
        ],
        # Next key event is when the old DNSKEY becomes HIDDEN.
        # This happens after the DNSKEY TTL plus zone propagation delay.
        "nextev": ALGOROLL_KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)


def test_algoroll_ksk_zsk_reconfig_step5(ns6, alg, size):
    zone = "step5.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The DNSKEY becomes HIDDEN.
            f"ksk 0 8 2048 goal:hidden dnskey:hidden krrsig:hidden ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:hidden zrrsig:unretentive offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step5']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step5']}",
        ],
        # Next key event is when the RSASHA signatures become HIDDEN.
        # This happens after the max-zone-ttl plus zone propagation delay
        # minus the time already passed since the UNRETENTIVE state has
        # been reached. Prevent intermittent false positives on slow
        # platforms by subtracting the number of seconds which passed
        # between key creation and invoking 'rndc reconfig'.
        "nextev": ALGOROLL_IRET - ALGOROLL_IRETKSK - ALGOROLL_KEYTTLPROP - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)


def test_algoroll_ksk_zsk_reconfig_step6(ns6, alg, size):
    zone = "step6.algorithm-roll.kasp"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The zone signatures are now HIDDEN.
            f"ksk 0 8 2048 goal:hidden dnskey:hidden krrsig:hidden ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:hidden zrrsig:hidden offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step6']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step6']}",
        ],
        # Next key event is never since we established the policy and the
        # keys have an unlimited lifetime.  Fallback to the default
        # loadkeys interval.
        "nextev": TIMEDELTA["PT1H"],
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, POLICY, step)
