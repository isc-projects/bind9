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
import shutil
import time

from datetime import timedelta

import dns
import dns.update
import pytest

pytest.importorskip("dns", minversion="2.0.0")
import isctest
from isctest.kasp import (
    KeyProperties,
    KeyTimingMetadata,
)

pytestmark = pytest.mark.extra_artifacts(
    [
        "K*.private",
        "K*.backup",
        "K*.cmp",
        "K*.key",
        "K*.state",
        "*.axfr",
        "*.created",
        "dig.out*",
        "keyevent.out.*",
        "keygen.out.*",
        "keys",
        "published.test*",
        "python.out.*",
        "retired.test*",
        "rndc.dnssec.*.out.*",
        "rndc.zonestatus.out.*",
        "rrsig.out.*",
        "created.key-*",
        "unused.key-*",
        "verify.out.*",
        "zone.out.*",
        "ns*/K*.key",
        "ns*/K*.offline",
        "ns*/K*.private",
        "ns*/K*.state",
        "ns*/*.db",
        "ns*/*.db.infile",
        "ns*/*.db.signed",
        "ns*/*.db.signed.tmp",
        "ns*/*.jbk",
        "ns*/*.jnl",
        "ns*/*.zsk1",
        "ns*/*.zsk2",
        "ns*/dsset-*",
        "ns*/keygen.out.*",
        "ns*/keys",
        "ns*/ksk",
        "ns*/ksk/K*",
        "ns*/zsk",
        "ns*/zsk",
        "ns*/zsk/K*",
        "ns*/named-fips.conf",
        "ns*/settime.out.*",
        "ns*/signer.out.*",
        "ns*/zones",
        "ns*/policies/*.conf",
        "ns3/legacy-keys.*",
        "ns3/dynamic-signed-inline-signing.kasp.db.signed.signed",
    ]
)


def check_all(server, zone, policy, ksks, zsks, tsig=None):
    isctest.kasp.check_dnssecstatus(server, zone, ksks + zsks, policy=policy)
    isctest.kasp.check_apex(server, zone, ksks, zsks, tsig=tsig)
    isctest.kasp.check_subdomain(server, zone, ksks, zsks, tsig=tsig)
    isctest.kasp.check_dnssec_verify(server, zone)


def set_keytimes_default_policy(kp):
    # The first key is immediately published and activated.
    kp.timing["Generated"] = kp.key.get_timing("Created")
    kp.timing["Published"] = kp.timing["Generated"]
    kp.timing["Active"] = kp.timing["Generated"]
    # The DS can be published if the DNSKEY and RRSIG records are
    # OMNIPRESENT.  This happens after max-zone-ttl (1d) plus
    # plus zone-propagation-delay (300s).
    kp.timing["PublishCDS"] = kp.timing["Published"] + timedelta(days=1, seconds=300)
    # Key lifetime is unlimited, so not setting 'Retired' nor 'Removed'.
    kp.timing["DNSKEYChange"] = kp.timing["Published"]
    kp.timing["DSChange"] = kp.timing["Published"]
    kp.timing["KRRSIGChange"] = kp.timing["Active"]
    kp.timing["ZRRSIGChange"] = kp.timing["Active"]


def test_kasp_default(servers):
    server = servers["ns3"]

    # check the zone with default kasp policy has loaded and is signed.
    isctest.log.info("check a zone with the default policy is signed")
    zone = "default.kasp"
    policy = "default"

    # Key properties.
    # DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
    keyprops = [
        "csk 0 13 256 goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
    ]
    expected = isctest.kasp.policy_to_properties(ttl=3600, keys=keyprops)
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    set_keytimes_default_policy(expected[0])
    isctest.kasp.check_keytimes(keys, expected)
    check_all(server, zone, policy, keys, [])

    # Trigger a keymgr run. Make sure the key files are not touched if there
    # are no modifications to the key metadata.
    isctest.log.info(
        "check that key files are untouched if there are no metadata changes"
    )
    key = keys[0]
    privkey_stat = os.stat(key.privatefile)
    pubkey_stat = os.stat(key.keyfile)
    state_stat = os.stat(key.statefile)

    with server.watch_log_from_here() as watcher:
        server.rndc(f"loadkeys {zone}", log=False)
        watcher.wait_for_line(f"keymgr: {zone} done")

    assert privkey_stat.st_mtime == os.stat(key.privatefile).st_mtime
    assert pubkey_stat.st_mtime == os.stat(key.keyfile).st_mtime
    assert state_stat.st_mtime == os.stat(key.statefile).st_mtime

    # again
    with server.watch_log_from_here() as watcher:
        server.rndc(f"loadkeys {zone}", log=False)
        watcher.wait_for_line(f"keymgr: {zone} done")

    assert privkey_stat.st_mtime == os.stat(key.privatefile).st_mtime
    assert pubkey_stat.st_mtime == os.stat(key.keyfile).st_mtime
    assert state_stat.st_mtime == os.stat(key.statefile).st_mtime

    # modify unsigned zone file and check that new record is signed.
    isctest.log.info("check that an updated zone signs the new record")
    shutil.copyfile("ns3/template2.db.in", f"ns3/{zone}.db")
    server.rndc(f"reload {zone}", log=False)

    def update_is_signed():
        parts = update.split()
        qname = parts[0]
        qtype = dns.rdatatype.from_text(parts[1])
        rdata = parts[2]
        return isctest.kasp.verify_update_is_signed(
            server, zone, qname, qtype, rdata, keys, []
        )

    expected_updates = [f"a.{zone}. A 10.0.0.11", f"d.{zone}. A 10.0.0.44"]
    for update in expected_updates:
        isctest.run.retry_with_timeout(update_is_signed, timeout=5)

    # Move the private key file, a rekey event should not introduce
    # replacement keys.
    isctest.log.info("check that missing private key doesn't trigger rollover")
    shutil.move(f"{key.privatefile}", f"{key.path}.offline")
    expectmsg = "zone_rekey:zone_verifykeys failed: some key files are missing"
    with server.watch_log_from_here() as watcher:
        server.rndc(f"loadkeys {zone}", log=False)
        watcher.wait_for_line(f"zone {zone}/IN (signed): {expectmsg}")
    # Nothing has changed.
    expected[0].properties["private"] = False
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_keytimes(keys, expected)
    check_all(server, zone, policy, keys, [])

    # A zone that uses inline-signing.
    isctest.log.info("check an inline-signed zone with the default policy is signed")
    zone = "inline-signing.kasp"
    # Key properties.
    key1 = KeyProperties.default()
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    expected = [key1]
    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    set_keytimes_default_policy(key1)
    isctest.kasp.check_keytimes(keys, expected)
    check_all(server, zone, policy, keys, [])


def test_kasp_dynamic(servers):
    # Dynamic update test cases.
    server = servers["ns3"]

    # Standard dynamic zone.
    isctest.log.info("check dynamic zone is updated and signed after update")
    zone = "dynamic.kasp"
    policy = "default"
    # Key properties.
    key1 = KeyProperties.default()
    expected = [key1]
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    set_keytimes_default_policy(key1)
    expected = [key1]
    isctest.kasp.check_keytimes(keys, expected)
    check_all(server, zone, policy, keys, [])

    # Update zone with nsupdate.
    def nsupdate(updates):
        message = dns.update.UpdateMessage(zone)
        for update in updates:
            if update[0] == "del":
                message.delete(update[1], update[2], update[3])
            else:
                assert update[0] == "add"
                message.add(update[1], update[2], update[3], update[4])

        try:
            response = isctest.query.udp(
                message, server.ip, server.ports.dns, timeout=3
            )
            assert response.rcode() == dns.rcode.NOERROR
        except dns.exception.Timeout:
            assert False, f"update timeout for {zone}"

        isctest.log.debug(f"update of zone {zone} to server {server.ip} successful")

    def update_is_signed():
        parts = update.split()
        qname = parts[0]
        qtype = dns.rdatatype.from_text(parts[1])
        rdata = parts[2]
        return isctest.kasp.verify_update_is_signed(
            server, zone, qname, qtype, rdata, keys, []
        )

    updates = [
        ["del", f"a.{zone}.", "A", "10.0.0.1"],
        ["add", f"a.{zone}.", 300, "A", "10.0.0.101"],
        ["add", f"d.{zone}.", 300, "A", "10.0.0.4"],
    ]
    nsupdate(updates)

    expected_updates = [f"a.{zone}. A 10.0.0.101", f"d.{zone}. A 10.0.0.4"]
    for update in expected_updates:
        isctest.run.retry_with_timeout(update_is_signed, timeout=5)

    # Update zone with nsupdate (reverting the above change).
    updates = [
        ["add", f"a.{zone}.", 300, "A", "10.0.0.1"],
        ["del", f"a.{zone}.", "A", "10.0.0.101"],
        ["del", f"d.{zone}.", "A", "10.0.0.4"],
    ]
    nsupdate(updates)

    update = f"a.{zone}. A 10.0.0.1"
    isctest.run.retry_with_timeout(update_is_signed, timeout=5)

    # Update zone with freeze/thaw.
    isctest.log.info("check dynamic zone is updated and signed after freeze and thaw")
    with server.watch_log_from_here() as watcher:
        server.rndc(f"freeze {zone}", log=False)
        watcher.wait_for_line(f"freezing zone '{zone}/IN': success")

    time.sleep(1)
    with open(f"ns3/{zone}.db", "a", encoding="utf-8") as zonefile:
        zonefile.write(f"d.{zone}. 300 A 10.0.0.44\n")
    time.sleep(1)

    with server.watch_log_from_here() as watcher:
        server.rndc(f"thaw {zone}", log=False)
        watcher.wait_for_line(f"thawing zone '{zone}/IN': success")

    expected_updates = [f"a.{zone}. A 10.0.0.1", f"d.{zone}. A 10.0.0.44"]

    for update in expected_updates:
        isctest.run.retry_with_timeout(update_is_signed, timeout=5)

    # Dynamic, and inline-signing.
    zone = "dynamic-inline-signing.kasp"
    # Key properties.
    key1 = KeyProperties.default()
    expected = [key1]
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    set_keytimes_default_policy(key1)
    expected = [key1]
    isctest.kasp.check_keytimes(keys, expected)
    check_all(server, zone, policy, keys, [])

    # Update zone with freeze/thaw.
    isctest.log.info(
        "check dynamic inline-signed zone is updated and signed after freeze and thaw"
    )
    with server.watch_log_from_here() as watcher:
        server.rndc(f"freeze {zone}", log=False)
        watcher.wait_for_line(f"freezing zone '{zone}/IN': success")

    time.sleep(1)
    shutil.copyfile("ns3/template2.db.in", f"ns3/{zone}.db")
    time.sleep(1)

    with server.watch_log_from_here() as watcher:
        server.rndc(f"thaw {zone}", log=False)
        watcher.wait_for_line(f"thawing zone '{zone}/IN': success")

    expected_updates = [f"a.{zone}. A 10.0.0.11", f"d.{zone}. A 10.0.0.44"]
    for update in expected_updates:
        isctest.run.retry_with_timeout(update_is_signed, timeout=5)

    # Dynamic, signed, and inline-signing.
    isctest.log.info("check dynamic signed, and inline-signed zone")
    zone = "dynamic-signed-inline-signing.kasp"
    # Key properties.
    key1 = KeyProperties.default()
    # The ns3/setup.sh script sets all states to omnipresent.
    key1.metadata["DNSKEYState"] = "omnipresent"
    key1.metadata["KRRSIGState"] = "omnipresent"
    key1.metadata["ZRRSIGState"] = "omnipresent"
    key1.metadata["DSState"] = "omnipresent"
    expected = [key1]
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3/keys")
    isctest.kasp.check_zone_is_signed(server, zone)
    isctest.kasp.check_keys(zone, keys, expected)
    check_all(server, zone, policy, keys, [])
    # Ensure no zone_resigninc for the unsigned version of the zone is triggered.
    assert f"zone_resigninc: zone {zone}/IN (unsigned): enter" not in "ns3/named.run"


def test_kasp_special_characters(servers):
    server = servers["ns3"]

    # A zone with special characters.
    isctest.log.info("check special characters")

    zone = r'i-am.":\;?&[]\@!\$*+,|=\.\(\)special.kasp'
    # It is non-trivial to adapt the tests to deal with all possible different
    # escaping characters, so we will just try to verify the zone.
    isctest.kasp.check_dnssec_verify(server, zone)


def test_kasp_insecure(servers):
    server = servers["ns3"]

    # Insecure zones.
    isctest.log.info("check insecure zones")

    zone = "insecure.kasp"
    expected = []
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy="insecure")
    isctest.kasp.check_apex(server, zone, keys, [])
    isctest.kasp.check_subdomain(server, zone, keys, [])

    zone = "unsigned.kasp"
    expected = []
    keys = isctest.kasp.keydir_to_keylist(zone, "ns3")
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_dnssecstatus(server, zone, keys, policy=None)
    isctest.kasp.check_apex(server, zone, keys, [])
    isctest.kasp.check_subdomain(server, zone, keys, [])
    # Make sure the zone file is untouched.
    isctest.check.file_contents_equal(f"ns3/{zone}.db.infile", f"ns3/{zone}.db")


def test_kasp_bad_maxzonettl(servers):
    server = servers["ns3"]

    # check that max-zone-ttl rejects zones with too high TTL.
    isctest.log.info("check max-zone-ttl rejects zones with too high TTL")
    zone = "max-zone-ttl.kasp"
    assert f"loading from master file {zone}.db failed: out of range" in server.log


def test_kasp_dnssec_keygen():
    def keygen(zone, policy, keydir=None):
        if keydir is None:
            keydir = "."

        keygen_command = [
            os.environ.get("KEYGEN"),
            "-K",
            keydir,
            "-k",
            policy,
            "-l",
            "kasp.conf",
            zone,
        ]

        return isctest.run.cmd(keygen_command, log_stdout=True).stdout.decode("utf-8")

    # check that 'dnssec-keygen -k' (configured policy) creates valid files.
    lifetime = {
        "P1Y": int(timedelta(days=365).total_seconds()),
        "P30D": int(timedelta(days=30).total_seconds()),
        "P6M": int(timedelta(days=31 * 6).total_seconds()),
    }
    keyprops = [
        f"csk {lifetime['P1Y']} 13 256",
        f"ksk {lifetime['P1Y']} 8 2048",
        f"zsk {lifetime['P30D']} 8 2048",
        f"zsk {lifetime['P6M']} 8 3072",
    ]
    keydir = "keys"
    out = keygen("kasp", "kasp", keydir)
    keys = isctest.kasp.keystr_to_keylist(out, keydir)
    expected = isctest.kasp.policy_to_properties(ttl=200, keys=keyprops)
    isctest.kasp.check_keys("kasp", keys, expected)

    # check that 'dnssec-keygen -k' (default policy) creates valid files.
    keyprops = ["csk 0 13 256"]
    out = keygen("kasp", "default")
    keys = isctest.kasp.keystr_to_keylist(out)
    expected = isctest.kasp.policy_to_properties(ttl=3600, keys=keyprops)
    isctest.kasp.check_keys("kasp", keys, expected)

    # check that 'dnssec-settime' by default does not edit key state file.
    key = keys[0]
    shutil.copyfile(key.privatefile, f"{key.privatefile}.backup")
    shutil.copyfile(key.keyfile, f"{key.keyfile}.backup")
    shutil.copyfile(key.statefile, f"{key.statefile}.backup")

    created = key.get_timing("Created")
    publish = key.get_timing("Publish") + timedelta(hours=1)
    settime = [
        os.environ.get("SETTIME"),
        "-P",
        str(publish),
        key.path,
    ]
    out = isctest.run.cmd(settime, log_stdout=True).stdout.decode("utf-8")

    isctest.check.file_contents_equal(f"{key.statefile}", f"{key.statefile}.backup")
    assert key.get_metadata("Publish", file=key.privatefile) == str(publish)
    assert key.get_metadata("Publish", file=key.keyfile, comment=True) == str(publish)

    # check that 'dnssec-settime -s' also sets publish time metadata and
    # states in key state file.
    now = KeyTimingMetadata.now()
    goal = "omnipresent"
    dnskey = "rumoured"
    krrsig = "rumoured"
    zrrsig = "omnipresent"
    ds = "hidden"
    keyprops = [
        f"csk 0 13 256 goal:{goal} dnskey:{dnskey} krrsig:{krrsig} zrrsig:{zrrsig} ds:{ds}",
    ]
    expected = isctest.kasp.policy_to_properties(ttl=3600, keys=keyprops)
    expected[0].timing = {
        "Generated": created,
        "Published": now,
        "Active": created,
        "DNSKEYChange": now,
        "KRRSIGChange": now,
        "ZRRSIGChange": now,
        "DSChange": now,
    }

    settime = [
        os.environ.get("SETTIME"),
        "-s",
        "-P",
        str(now),
        "-g",
        goal,
        "-k",
        dnskey,
        str(now),
        "-r",
        krrsig,
        str(now),
        "-z",
        zrrsig,
        str(now),
        "-d",
        ds,
        str(now),
        key.path,
    ]
    out = isctest.run.cmd(settime, log_stdout=True).stdout.decode("utf-8")
    isctest.kasp.check_keys("kasp", keys, expected)
    isctest.kasp.check_keytimes(keys, expected)

    # check that 'dnssec-settime -s' also unsets publish time metadata and
    # states in key state file.
    now = KeyTimingMetadata.now()
    keyprops = ["csk 0 13 256"]
    expected = isctest.kasp.policy_to_properties(ttl=3600, keys=keyprops)
    expected[0].timing = {
        "Generated": created,
        "Active": created,
    }

    settime = [
        os.environ.get("SETTIME"),
        "-s",
        "-P",
        "none",
        "-g",
        "none",
        "-k",
        "none",
        str(now),
        "-z",
        "none",
        str(now),
        "-r",
        "none",
        str(now),
        "-d",
        "none",
        str(now),
        key.path,
    ]
    out = isctest.run.cmd(settime, log_stdout=True).stdout.decode("utf-8")
    isctest.kasp.check_keys("kasp", keys, expected)
    isctest.kasp.check_keytimes(keys, expected)

    # check that 'dnssec-settime -s' also sets active time metadata and states in key state file (uppercase)
    soon = now + timedelta(hours=2)
    goal = "hidden"
    dnskey = "unretentive"
    krrsig = "omnipresent"
    zrrsig = "unretentive"
    ds = "omnipresent"
    keyprops = [
        f"csk 0 13 256 goal:{goal} dnskey:{dnskey} krrsig:{krrsig} zrrsig:{zrrsig} ds:{ds}",
    ]
    expected = isctest.kasp.policy_to_properties(ttl=3600, keys=keyprops)
    expected[0].timing = {
        "Generated": created,
        "Active": soon,
        "DNSKEYChange": soon,
        "KRRSIGChange": soon,
        "ZRRSIGChange": soon,
        "DSChange": soon,
    }

    settime = [
        os.environ.get("SETTIME"),
        "-s",
        "-A",
        str(soon),
        "-g",
        "HIDDEN",
        "-k",
        "UNRETENTIVE",
        str(soon),
        "-z",
        "UNRETENTIVE",
        str(soon),
        "-r",
        "OMNIPRESENT",
        str(soon),
        "-d",
        "OMNIPRESENT",
        str(soon),
        key.path,
    ]
    out = isctest.run.cmd(settime, log_stdout=True).stdout.decode("utf-8")
    isctest.kasp.check_keys("kasp", keys, expected)
    isctest.kasp.check_keytimes(keys, expected)
