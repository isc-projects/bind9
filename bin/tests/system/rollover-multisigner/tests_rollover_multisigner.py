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
import os

import pytest

pytest.importorskip("dns", minversion="2.0.0")
import dns.update

import isctest
from isctest.kasp import Iret
from rollover.common import (
    pytestmark,
    alg,
    size,
)


def test_rollover_multisigner(ns3, alg, size):
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

    isctest.kasp.wait_keymgr_done(ns3, zone)

    isctest.kasp.check_dnssec_verify(ns3, zone)

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

    ownkeys = isctest.kasp.keydir_to_keylist(zone, ns3.identifier)
    extkeys = isctest.kasp.keydir_to_keylist(zone)
    keys = ownkeys + extkeys
    ksks = [k for k in ownkeys if k.is_ksk()]
    zsks = [k for k in ownkeys if not k.is_ksk()]
    zsks = zsks + extkeys

    isctest.kasp.check_keys(zone, keys, expected)
    for kp in expected:
        kp.set_expected_keytimes(config)
    isctest.kasp.check_keytimes(keys, expected)
    isctest.kasp.check_dnssecstatus(ns3, zone, keys, policy=policy)
    isctest.kasp.check_apex(ns3, zone, ksks, zsks)
    isctest.kasp.check_subdomain(ns3, zone, ksks, zsks)

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
    ns3.nsupdate(update_msg)

    isctest.kasp.check_dnssec_verify(ns3, zone)

    keys = keys + newkeys
    zsks = zsks + newkeys
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(ns3, zone, ksks, zsks)
    isctest.kasp.check_subdomain(ns3, zone, ksks, zsks)

    # Remove ZSKs from the other providers for zone.
    dnskey2 = extkeys[0].dnskey().split()
    rdata2 = " ".join(dnskey2[4:])
    update_msg = dns.update.UpdateMessage(zone)
    update_msg.delete(f"{dnskey[0]}", "DNSKEY", rdata)
    update_msg.delete(f"{dnskey2[0]}", "DNSKEY", rdata2)
    ns3.nsupdate(update_msg)

    isctest.kasp.check_dnssec_verify(ns3, zone)

    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = ownkeys
    ksks = [k for k in ownkeys if k.is_ksk()]
    zsks = [k for k in ownkeys if not k.is_ksk()]
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_apex(ns3, zone, ksks, zsks)
    isctest.kasp.check_subdomain(ns3, zone, ksks, zsks)

    # A zone transitioning from single-signed to multi-signed. We should have
    # the old omnipresent keys outside of the desired key range and the new
    # keys in the desired key range.
    zone = "single-to-multisigner.kasp"

    isctest.kasp.wait_keymgr_done(ns3, zone)

    isctest.kasp.check_dnssec_verify(ns3, zone)

    key_properties = [
        f"ksk unlimited {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden tag-range:32768-65535",
        f"zsk unlimited {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:hidden tag-range:32768-65535",
        f"ksk unlimited {alg} {size} goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent tag-range:0-32767 offset:{offval}",
        f"zsk unlimited {alg} {size} goal:hidden dnskey:omnipresent zrrsig:omnipresent tag-range:0-32767 offset:{offval}",
    ]
    expected = isctest.kasp.policy_to_properties(ttl, key_properties)
    keys = isctest.kasp.keydir_to_keylist(zone, ns3.identifier)
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
    isctest.kasp.check_dnssecstatus(ns3, zone, keys, policy=policy)
    isctest.kasp.check_apex(ns3, zone, ksks, zsks)
    isctest.kasp.check_subdomain(ns3, zone, ksks, zsks)
