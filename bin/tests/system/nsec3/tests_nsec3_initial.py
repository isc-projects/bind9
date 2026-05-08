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

# pylint: disable=unspecified-encoding,multiple-statements,use-maxsplit-arg,broad-exception-caught,f-string-without-interpolation

import os

import dns.rcode
import dns.rdatatype
import dns.update
import pytest

from isctest.algorithms import RSASHA1, Algorithm
from nsec3.common import (
    NSEC3_MARK,
    NSEC3_SALTLEN,
    check_nsec3_case,
    wait_for_nsec3param,
)

import isctest
import isctest.mark

pytestmark = NSEC3_MARK

# include the following zones when rendering named configs
ZONES = {
    "nsec-to-nsec3.kasp",
    "nsec3-xfr-inline.kasp",
    "nsec3-dynamic-update-inline.kasp",
    "nsec3.kasp",
    "nsec3-dynamic.kasp",
    "nsec3-private-type-delete.kasp",
    "nsec3-change.kasp",
    "nsec3-dynamic-change.kasp",
    "nsec3-dynamic-to-inline.kasp",
    "nsec3-inline-to-dynamic.kasp",
    "nsec3-to-nsec.kasp",
    "nsec3-to-nsec-altalg.kasp",
    "nsec3-to-optout.kasp",
    "nsec3-from-optout.kasp",
    "nsec3-other.kasp",
}

if os.environ["RSASHA1_SUPPORTED"] == "1":
    ZONES.update(
        {
            "rsasha1-to-nsec3.kasp",
            "rsasha1-to-nsec3-wait.kasp",
            "nsec3-to-rsasha1.kasp",
            "nsec3-to-rsasha1-ds.kasp",
        }
    )


def bootstrap():
    return {
        "zones": ZONES,
    }


@pytest.fixture(scope="module", autouse=True)
def after_servers_start(ns3):
    # Make sure the zones are properly signed.
    for zone in ZONES:
        isctest.kasp.wait_keymgr_done(ns3, zone)
        wait_for_nsec3param(ns3, zone, NSEC3_SALTLEN[zone].initial)


def test_update_delete_private_type_rrset(ns3):
    zone = "nsec3-private-type-delete.kasp"
    fqdn = f"{zone}."

    update_msg = dns.update.UpdateMessage(zone)
    update_msg.add(fqdn, 0, dns.rdatatype.NSEC3PARAM, "1 0 5 ab")
    response = isctest.query.tcp(
        update_msg,
        ns3.ip,
        attempts=1,
        expected_rcode=dns.rcode.NOERROR,
    )
    isctest.check.noerror(response)

    update_msg = dns.update.UpdateMessage(zone)
    update_msg.delete(fqdn, dns.rdatatype.from_text("TYPE65534"))
    response = isctest.query.tcp(
        update_msg,
        ns3.ip,
        attempts=1,
        expected_rcode=dns.rcode.NOERROR,
    )
    isctest.check.noerror(response)


def test_update_delete_all_apex_rrsets_with_private_type(ns3):
    zone = "nsec3-private-type-delete.kasp"
    fqdn = f"{zone}."

    update_msg = dns.update.UpdateMessage(zone)
    update_msg.add(fqdn, 0, dns.rdatatype.NSEC3PARAM, "1 0 5 ab")
    response = isctest.query.tcp(
        update_msg,
        ns3.ip,
        attempts=1,
        expected_rcode=dns.rcode.NOERROR,
    )
    isctest.check.noerror(response)

    update_msg = dns.update.UpdateMessage(zone)
    update_msg.delete(fqdn)
    response = isctest.query.tcp(
        update_msg,
        ns3.ip,
        attempts=1,
        expected_rcode=dns.rcode.NOERROR,
    )
    isctest.check.noerror(response)


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "nsec-to-nsec3.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec-to-nsec3.kasp",
        ),
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="rsasha1-to-nsec3.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3-wait.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="rsasha1-to-nsec3-wait.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                # This is a secondary zone, where the primary is signed with
                # NSEC3 but the dnssec-policy dictates NSEC.
                "zone": "nsec3-xfr-inline.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
                "external-keys": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits}",
                ],
                "external-keydir": "ns2",
            },
            id="nsec3-xfr-inline.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-update-inline.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-update-inline.kasp",
        ),
    ],
)
def test_nsec_case(ns3, params):
    # Get test parameters.
    zone = params["zone"]

    # Test case.
    check_nsec3_case(ns3, params, nsec3=False)

    # Extra test for nsec3-dynamic-update-inline.kasp.
    if zone == "nsec3-dynamic-update-inline.kasp":
        isctest.log.info(f"dynamic update dnssec-policy zone {zone} with NSEC3")
        update_msg = dns.update.UpdateMessage(zone)
        update_msg.add(
            f"04O18462RI5903H8RDVL0QDT5B528DUJ.{zone}.",
            3600,
            "NSEC3",
            "0 0 0 408A4B2D412A4E95 1JMDDPMTFF8QQLIOINSIG4CR9OTICAOC A RRSIG",
        )

        with ns3.watch_log_from_here() as watcher:
            ns3.nsupdate(update_msg, expected_rcode=dns.rcode.REFUSED)
            watcher.wait_for_line(
                f"updating zone '{zone}/IN': update failed: explicit NSEC3 updates are not allowed in secure zones (REFUSED)"
            )


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="nsec3-to-rsasha1.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1-ds.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="nsec3-to-rsasha1-ds.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-change.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-change.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-change.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-change.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-to-inline.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-to-inline.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-inline-to-dynamic.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-inline-to-dynamic.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-to-nsec.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-nsec.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-to-nsec-altalg.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="nsec3-to-nsec-altalg.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-to-optout.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-optout.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-from-optout.kasp",
                "policy": "optout",
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 0,
                },
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-from-optout.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-other.kasp",
                "policy": "nsec3-other",
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 8,
                },
                "key-properties": [
                    f"csk 0 {Algorithm.default().number} {Algorithm.default().bits} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-other.kasp",
        ),
    ],
)
def test_nsec3_case(ns3, params):
    check_nsec3_case(ns3, params)
