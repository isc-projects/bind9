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

import os

from datetime import timedelta

import pytest

pytest.importorskip("dns", minversion="2.0.0")
import dns.update

import isctest
from isctest.kasp import KeyTimingMetadata, Ipub, IpubC, Iret

from common import pytestmark


def test_rollover_manual(servers):
    server = servers["ns3"]
    policy = "manual-rollover"
    config = {
        "dnskey-ttl": timedelta(hours=1),
        "ds-ttl": timedelta(days=1),
        "max-zone-ttl": timedelta(days=1),
        "parent-propagation-delay": timedelta(hours=1),
        "publish-safety": timedelta(hours=1),
        "retire-safety": timedelta(hours=1),
        "signatures-refresh": timedelta(days=7),
        "signatures-validity": timedelta(days=14),
        "zone-propagation-delay": timedelta(minutes=5),
    }
    ttl = int(config["dnskey-ttl"].total_seconds())
    alg = os.environ["DEFAULT_ALGORITHM_NUMBER"]
    size = os.environ["DEFAULT_BITS"]
    zone = "manual-rollover.kasp"

    with server.watch_log_from_start() as watcher:
        watcher.wait_for_line(f"keymgr: {zone} done")

    isctest.kasp.check_dnssec_verify(server, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    ksks = [k for k in keys if k.is_ksk()]
    zsks = [k for k in keys if not k.is_ksk()]

    isctest.kasp.check_keys(zone, keys, expected)

    offset = -timedelta(days=7)
    for kp in expected:
        kp.set_expected_keytimes(config, offset=offset)

    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # Schedule KSK rollover in six months.
    assert len(ksks) == 1
    ksk = ksks[0]
    startroll = expected[0].timing["Active"] + timedelta(days=30 * 6)
    expected[0].timing["Retired"] = startroll + Ipub(config)
    expected[0].timing["Removed"] = expected[0].timing["Retired"] + Iret(
        config, zsk=False, ksk=True
    )

    with server.watch_log_from_here() as watcher:
        server.rndc(f"dnssec -rollover -key {ksk.tag} -when {startroll} {zone}")
        watcher.wait_for_line(f"keymgr: {zone} done")

    isctest.kasp.check_dnssec_verify(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # Schedule KSK rollover now.
    now = KeyTimingMetadata.now()
    with server.watch_log_from_here() as watcher:
        server.rndc(f"dnssec -rollover -key {ksk.tag} -when {now} {zone}")
        watcher.wait_for_line(f"keymgr: {zone} done")

    isctest.kasp.check_dnssec_verify(server, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent",
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    ksks = [k for k in keys if k.is_ksk()]
    zsks = [k for k in keys if not k.is_ksk()]

    isctest.kasp.check_keys(zone, keys, expected)

    expected[0].metadata["Successor"] = expected[1].key.tag
    expected[1].metadata["Predecessor"] = expected[0].key.tag
    isctest.kasp.check_keyrelationships(keys, expected)

    for kp in expected:
        off = offset
        if "Predecessor" in kp.metadata:
            off = 0
        kp.set_expected_keytimes(config, offset=off)

    expected[0].timing["Retired"] = now + Ipub(config)
    expected[0].timing["Removed"] = expected[0].timing["Retired"] + Iret(
        config, zsk=False, ksk=True
    )

    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # Schedule ZSK rollover now.
    assert len(zsks) == 1
    zsk = zsks[0]
    now = KeyTimingMetadata.now()
    with server.watch_log_from_here() as watcher:
        server.rndc(f"dnssec -rollover -key {zsk.tag} -when {now} {zone}")
        watcher.wait_for_line(f"keymgr: {zone} done")

    isctest.kasp.check_dnssec_verify(server, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent",
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden",
        f"zsk unlimited {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:hidden",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    ksks = [k for k in keys if k.is_ksk()]
    zsks = [k for k in keys if not k.is_ksk()]

    isctest.kasp.check_keys(zone, keys, expected)

    expected[0].metadata["Successor"] = expected[1].key.tag
    expected[1].metadata["Predecessor"] = expected[0].key.tag
    expected[2].metadata["Successor"] = expected[3].key.tag
    expected[3].metadata["Predecessor"] = expected[2].key.tag
    isctest.kasp.check_keyrelationships(keys, expected)

    # Try to schedule a ZSK rollover for an inactive key (should fail).
    zsk = expected[3].key
    response = server.rndc(f"dnssec -rollover -key {zsk.tag} {zone}")
    assert "key is not actively signing" in response


def test_rollover_multisigner(servers):
    server = servers["ns3"]
    policy = "multisigner-model2"
    config = {
        "dnskey-ttl": timedelta(hours=1),
        "ds-ttl": timedelta(days=1),
        "max-zone-ttl": timedelta(days=1),
        "parent-propagation-delay": timedelta(hours=1),
        "publish-safety": timedelta(hours=1),
        "retire-safety": timedelta(hours=1),
        "signatures-refresh": timedelta(days=5),
        "signatures-validity": timedelta(days=14),
        "zone-propagation-delay": timedelta(minutes=5),
    }
    ttl = int(config["dnskey-ttl"].total_seconds())
    alg = os.environ["DEFAULT_ALGORITHM_NUMBER"]
    size = os.environ["DEFAULT_BITS"]

    offset = -timedelta(days=7)
    offval = int(offset.total_seconds())

    def keygen(zone):
        keygen_command = [
            os.environ.get("KEYGEN"),
            "-a",
            alg,
            "-L",
            "3600",
            "-M",
            "0:32767",
            zone,
        ]

        return isctest.run.cmd(keygen_command).stdout.decode("utf-8")

    zone = "multisigner-model2.kasp"

    isctest.kasp.check_dnssec_verify(server, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden tag-range:32768-65535",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:rumoured tag-range:32768-65535",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)

    newprops = [f"zsk unlimited {alg} {size} tag-range:0-32767"]
    expected2 = isctest.kasp.policy_to_properties(ttl, newprops)
    expected2[0].properties["private"] = False
    expected2[0].properties["legacy"] = True
    expected = expected + expected2

    ownkeys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    extkeys = isctest.kasp.keydir_to_keylist(zone)
    keys = ownkeys + extkeys
    ksks = [k for k in ownkeys if k.is_ksk()]
    zsks = [k for k in ownkeys if not k.is_ksk()]
    zsks = zsks + extkeys

    isctest.kasp.check_keys(zone, keys, expected)
    for kp in expected:
        kp.set_expected_keytimes(config)
    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # Update zone with ZSK from another provider for zone.
    out = keygen(zone)
    newkeys = isctest.kasp.keystr_to_keylist(out)
    newprops = [f"zsk unlimited {alg} {size} tag-range:0-32767"]
    expected2 = isctest.kasp.policy_to_properties(ttl, newprops)
    expected2[0].properties["private"] = False
    expected2[0].properties["legacy"] = True
    expected = expected + expected2

    dnskey = newkeys[0].dnskey().split()
    rdata = " ".join(dnskey[4:])

    update_msg = dns.update.UpdateMessage(zone)
    update_msg.add(f"{dnskey[0]}", 3600, "DNSKEY", rdata)
    server.nsupdate(update_msg)

    isctest.kasp.check_dnssec_verify(server, zone)

    keys = keys + newkeys
    zsks = zsks + newkeys
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # Remove ZSKs from the other providers for zone.
    dnskey2 = extkeys[0].dnskey().split()
    rdata2 = " ".join(dnskey2[4:])
    update_msg = dns.update.UpdateMessage(zone)
    update_msg.delete(f"{dnskey[0]}", "DNSKEY", rdata)
    update_msg.delete(f"{dnskey2[0]}", "DNSKEY", rdata2)
    server.nsupdate(update_msg)

    isctest.kasp.check_dnssec_verify(server, zone)

    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = ownkeys
    ksks = [k for k in ownkeys if k.is_ksk()]
    zsks = [k for k in ownkeys if not k.is_ksk()]
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)

    # A zone transitioning from single-signed to multi-signed. We should have
    # the old omnipresent keys outside of the desired key range and the new
    # keys in the desired key range.
    zone = "single-to-multisigner.kasp"

    isctest.kasp.check_dnssec_verify(server, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden tag-range:32768-65535",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:hidden tag-range:32768-65535",
        f"ksk unlimited {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent tag-range:0-32767 offset:{offval}",
        f"zsk unlimited {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent tag-range:0-32767 offset:{offval}",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    ksks = [k for k in keys if k.is_ksk()]
    zsks = [k for k in keys if not k.is_ksk()]

    isctest.kasp.check_keys(zone, keys, expected)

    for kp in expected:
        kp.set_expected_keytimes(config)

    start = expected[0].key.get_timing("Created")
    expected[2].timing["Retired"] = start
    expected[2].timing["Removed"] = expected[2].timing["Retired"] + Iret(
        config, zsk=False, ksk=True
    )
    expected[3].timing["Retired"] = start
    expected[3].timing["Removed"] = expected[3].timing["Retired"] + Iret(
        config, zsk=True, ksk=False
    )

    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)


def test_rollover_enable_dnssec(servers):
    server = servers["ns3"]
    policy = "enable-dnssec"
    cdss = ["CDNSKEY", "CDS (SHA-256)"]
    config = {
        "dnskey-ttl": timedelta(seconds=300),
        "ds-ttl": timedelta(hours=2),
        "max-zone-ttl": timedelta(hours=12),
        "parent-propagation-delay": timedelta(hours=1),
        "publish-safety": timedelta(minutes=5),
        "retire-safety": timedelta(minutes=20),
        "signatures-refresh": timedelta(days=7),
        "signatures-validity": timedelta(days=14),
        "zone-propagation-delay": timedelta(minutes=5),
    }
    alg = os.environ["DEFAULT_ALGORITHM_NUMBER"]
    size = os.environ["DEFAULT_BITS"]

    ipub = Ipub(config)
    ipubC = IpubC(config, rollover=False)
    iretZSK = Iret(config, rollover=False)
    iretKSK = Iret(config, zsk=False, ksk=True, rollover=False)
    offsets = {
        "step1": 0,
        "step2": -int(ipub.total_seconds()),
        "step3": -int(iretZSK.total_seconds()),
        "step4": -int(ipubC.total_seconds() + iretKSK.total_seconds()),
    }

    steps = [
        {
            # Step 1.
            "zone": "step1.enable-dnssec.autosign",
            "cdss": cdss,
            "keyprops": [
                f"csk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden offset:{offsets['step1']}",
            ],
            # Next key event is when the DNSKEY RRset becomes OMNIPRESENT,
            # after the publication interval.
            "nextev": ipub,
        },
        {
            # Step 2.
            "zone": "step2.enable-dnssec.autosign",
            "cdss": cdss,
            # The DNSKEY is omnipresent, but the zone signatures not yet.
            # Thus, the DS remains hidden.
            # dnskey: rumoured -> omnipresent
            # krrsig: rumoured -> omnipresent
            "keyprops": [
                f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:rumoured ds:hidden offset:{offsets['step2']}",
            ],
            # Next key event is when the zone signatures become OMNIPRESENT,
            # Minus the time already elapsed.
            "nextev": iretZSK - ipub,
        },
        {
            # Step 3.
            "zone": "step3.enable-dnssec.autosign",
            "cdss": cdss,
            # All signatures should be omnipresent, so the DS can be submitted.
            # zrrsig: rumoured -> omnipresent
            # ds: hidden -> rumoured
            "keyprops": [
                f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:rumoured offset:{offsets['step3']}",
            ],
            # Next key event is when the DS can move to the OMNIPRESENT state.
            # This is after the retire interval.
            "nextev": iretKSK,
        },
        {
            # Step 4.
            "zone": "step4.enable-dnssec.autosign",
            "cdss": cdss,
            # DS has been published long enough.
            # ds: rumoured -> omnipresent
            "keyprops": [
                f"csk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent offset:{offsets['step4']}",
            ],
            # Next key event is never, the zone dnssec-policy has been
            # established. So we fall back to the default loadkeys interval.
            "nextev": timedelta(hours=1),
        },
    ]

    for step in steps:
        isctest.kasp.check_rollover_step(server, config, policy, step)


def test_rollover_zsk_prepublication(servers):
    server = servers["ns3"]
    policy = "zsk-prepub"
    config = {
        "dnskey-ttl": timedelta(seconds=3600),
        "ds-ttl": timedelta(days=1),
        "max-zone-ttl": timedelta(days=1),
        "parent-propagation-delay": timedelta(hours=1),
        "publish-safety": timedelta(days=1),
        "purge-keys": timedelta(hours=1),
        "retire-safety": timedelta(days=2),
        "signatures-refresh": timedelta(days=7),
        "signatures-validity": timedelta(days=14),
        "zone-propagation-delay": timedelta(hours=1),
    }
    alg = os.environ["DEFAULT_ALGORITHM_NUMBER"]
    size = os.environ["DEFAULT_BITS"]
    zsk_lifetime = timedelta(days=30)
    lifetime_policy = int(zsk_lifetime.total_seconds())

    ipub = Ipub(config)
    iret = Iret(config, rollover=True)
    keyttlprop = config["dnskey-ttl"] + config["zone-propagation-delay"]
    offsets = {}
    offsets["step1-p"] = -int(timedelta(days=7).total_seconds())
    offsets["step2-p"] = -int(zsk_lifetime.total_seconds() - ipub.total_seconds())
    offsets["step2-s"] = 0
    offsets["step3-p"] = -int(zsk_lifetime.total_seconds())
    offsets["step3-s"] = -int(ipub.total_seconds())
    offsets["step4-p"] = offsets["step3-p"] - int(iret.total_seconds())
    offsets["step4-s"] = offsets["step3-s"] - int(iret.total_seconds())
    offsets["step5-p"] = offsets["step4-p"] - int(keyttlprop.total_seconds())
    offsets["step5-s"] = offsets["step4-s"] - int(keyttlprop.total_seconds())
    offsets["step6-p"] = offsets["step5-p"] - int(config["purge-keys"].total_seconds())
    offsets["step6-s"] = offsets["step5-s"] - int(config["purge-keys"].total_seconds())

    steps = [
        {
            # Step 1.
            # Introduce the first key. This will immediately be active.
            "zone": "step1.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step1-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{offsets['step1-p']}",
            ],
            # Next key event is when the successor ZSK needs to be published.
            # That is the ZSK lifetime - prepublication time (minus time
            # already passed).
            "nextev": zsk_lifetime - ipub - timedelta(days=7),
        },
        {
            # Step 2.
            # It is time to pre-publish the successor ZSK.
            # ZSK1 goal: omnipresent -> hidden
            # ZSK2 goal: hidden -> omnipresent
            # ZSK2 dnskey: hidden -> rumoured
            "zone": "step2.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step2-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{offsets['step2-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:hidden offset:{offsets['step2-s']}",
            ],
            "keyrelationships": [1, 2],
            # Next key event is when the successor ZSK becomes OMNIPRESENT.
            # That is the DNSKEY TTL plus the zone propagation delay
            "nextev": ipub,
        },
        {
            # Step 3.
            # Predecessor ZSK is no longer actively signing. Successor ZSK is
            # now actively signing.
            # ZSK1 zrrsig: omnipresent -> unretentive
            # ZSK2 dnskey: rumoured -> omnipresent
            # ZSK2 zrrsig: hidden -> rumoured
            "zone": "step3.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step3-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:hidden dnskey:omnipresent zrrsig:unretentive offset:{offsets['step3-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:rumoured offset:{offsets['step3-s']}",
            ],
            "keyrelationships": [1, 2],
            # Next key event is when all the RRSIG records have been replaced
            # with signatures of the new ZSK, in other words when ZRRSIG
            # becomes OMNIPRESENT.
            "nextev": iret,
            # Set 'smooth' to true so expected signatures of subdomain are
            # from the predecessor ZSK.
            "smooth": True,
        },
        {
            # Step 4.
            # Predecessor ZSK is no longer needed. All RRsets are signed with
            # the successor ZSK.
            # ZSK1 dnskey: omnipresent -> unretentive
            # ZSK1 zrrsig: unretentive -> hidden
            # ZSK2 zrrsig: rumoured -> omnipresent
            "zone": "step4.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step4-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:hidden dnskey:unretentive zrrsig:hidden offset:{offsets['step4-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{offsets['step4-s']}",
            ],
            "keyrelationships": [1, 2],
            # Next key event is when the DNSKEY enters the HIDDEN state.
            # This is the DNSKEY TTL plus zone propagation delay.
            "nextev": keyttlprop,
        },
        {
            # Step 5.
            # Predecessor ZSK is now removed.
            # ZSK1 dnskey: unretentive -> hidden
            "zone": "step5.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step5-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:hidden dnskey:hidden zrrsig:hidden offset:{offsets['step5-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{offsets['step5-s']}",
            ],
            "keyrelationships": [1, 2],
            # Next key event is when the new successor needs to be published.
            # This is the ZSK lifetime minus Iret minus Ipub minus time
            # elapsed.
            "nextev": zsk_lifetime - iret - ipub - keyttlprop,
        },
        {
            # Step 6.
            # Predecessor ZSK is now purged.
            "zone": "step6.zsk-prepub.autosign",
            "keyprops": [
                f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{offsets['step6-p']}",
                f"zsk {lifetime_policy} {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{offsets['step6-s']}",
            ],
            "nextev": None,
        },
    ]

    for step in steps:
        isctest.kasp.check_rollover_step(server, config, policy, step)
