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
from isctest.kasp import KeyTimingMetadata

pytestmark = pytest.mark.extra_artifacts(
    [
        "*.axfr*",
        "dig.out*",
        "K*.key*",
        "K*.private*",
        "ns*/*.db",
        "ns*/*.db.infile",
        "ns*/*.db.jnl",
        "ns*/*.db.jbk",
        "ns*/*.db.signed",
        "ns*/*.db.signed.jnl",
        "ns*/*.conf",
        "ns*/dsset-*",
        "ns*/K*.key",
        "ns*/K*.private",
        "ns*/K*.state",
        "ns*/keygen.out.*",
        "ns*/settime.out.*",
        "ns*/signer.out.*",
        "ns*/zones",
    ]
)


def Ipub(config):
    return (
        config["dnskey-ttl"]
        + config["zone-propagation-delay"]
        + config["publish-safety"]
    )


def IpubC(config, rollover=True):
    if rollover:
        ttl = config["dnskey-ttl"]
        safety_interval = config["publish-safety"]
    else:
        ttl = config["max-zone-ttl"]
        safety_interval = timedelta(0)

    return ttl + config["zone-propagation-delay"] + safety_interval


def Iret(config, zsk=True, ksk=False, rollover=True):
    sign_delay = timedelta(0)
    safety_interval = timedelta(0)
    if rollover:
        sign_delay = config["signatures-validity"] - config["signatures-refresh"]
        safety_interval = config["retire-safety"]

    iretKSK = timedelta(0)
    if ksk:
        # KSK: Double-KSK Method: Iret = DprpP + TTLds
        iretKSK = (
            config["parent-propagation-delay"] + config["ds-ttl"] + safety_interval
        )

    iretZSK = timedelta(0)
    if zsk:
        # ZSK: Pre-Publication Method: Iret = Dsgn + Dprp + TTLsig
        iretZSK = (
            sign_delay
            + config["zone-propagation-delay"]
            + config["max-zone-ttl"]
            + safety_interval
        )

    return max(iretKSK, iretZSK)


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
    key_properties = [
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, server.identifier)
    ksks = [k for k in keys if k.is_ksk()]
    zsks = [k for k in keys if not k.is_ksk()]

    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)

    offset = -timedelta(days=7)
    for kp in expected:
        kp.set_expected_keytimes(config, offset=offset)

    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)
    isctest.kasp.check_dnssec_verify(server, zone)

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

    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)
    isctest.kasp.check_dnssec_verify(server, zone)

    # Schedule KSK rollover now.
    now = KeyTimingMetadata.now()
    with server.watch_log_from_here() as watcher:
        server.rndc(f"dnssec -rollover -key {ksk.tag} -when {now} {zone}")
        watcher.wait_for_line(f"keymgr: {zone} done")

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
    isctest.kasp.check_dnssec_verify(server, zone)

    # Schedule ZSK rollover now.
    assert len(zsks) == 1
    zsk = zsks[0]
    now = KeyTimingMetadata.now()
    with server.watch_log_from_here() as watcher:
        server.rndc(f"dnssec -rollover -key {zsk.tag} -when {now} {zone}")
        watcher.wait_for_line(f"keymgr: {zone} done")

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

        return isctest.run.cmd(keygen_command, log_stdout=True).stdout.decode("utf-8")

    def nsupdate(updates):
        message = dns.update.UpdateMessage(zone)
        for update in updates:
            if update[0] == 0:
                message.delete(update[1], update[2], update[3])
            else:
                message.add(update[1], update[2], update[3], update[4])

        try:
            response = isctest.query.udp(
                message, server.ip, server.ports.dns, timeout=3
            )
            assert response.rcode() == dns.rcode.NOERROR
        except dns.exception.Timeout:
            isctest.log.info(f"error: update timeout for {zone}")

    zone = "multisigner-model2.kasp"
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

    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    for kp in expected:
        kp.set_expected_keytimes(config)
    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)
    isctest.kasp.check_dnssec_verify(server, zone)

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

    updates = [[1, f"{dnskey[0]}", 3600, "DNSKEY", rdata]]
    nsupdate(updates)

    keys = keys + newkeys
    zsks = zsks + newkeys
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)
    isctest.kasp.check_dnssec_verify(server, zone)

    # Remove ZSKs from the other providers for zone.
    dnskey2 = extkeys[0].dnskey().split()
    rdata2 = " ".join(dnskey2[4:])
    updates = [
        [0, f"{dnskey[0]}", "DNSKEY", rdata],
        [0, f"{dnskey2[0]}", "DNSKEY", rdata2],
    ]
    nsupdate(updates)

    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = ownkeys
    ksks = [k for k in ownkeys if k.is_ksk()]
    zsks = [k for k in ownkeys if not k.is_ksk()]
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(server, zone, ksks, zsks)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks)
    isctest.kasp.check_dnssec_verify(server, zone)

    # A zone transitioning from single-signed to multi-signed. We should have
    # the old omnipresent keys outside of the desired key range and the new
    # keys in the desired key range.
    zone = "single-to-multisigner.kasp"
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

    isctest.kasp.check_zone_is_signed(server, zone)
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
    isctest.kasp.check_dnssec_verify(server, zone)
