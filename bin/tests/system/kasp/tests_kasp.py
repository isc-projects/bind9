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

from datetime import timedelta

import pytest

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
        "ns*/K*.private",
        "ns*/K*.key",
        "ns*/K*.state",
        "ns*/*.db",
        "ns*/*.db.infile",
        "ns*/*.db.signed",
        "ns*/*.jbk",
        "ns*/*.jnl",
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
        "ns*/*.zsk1",
        "ns*/*.zsk2",
        "ns3/legacy-keys.*",
        "ns3/dynamic-signed-inline-signing.kasp.db.signed.signed",
    ]
)


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
        "P6M": int(timedelta(days=31*6).total_seconds()),
    }
    keyprops = [
        f"csk {lifetime['P1Y']} 13 256",
        f"ksk {lifetime['P1Y']} 8 2048",
        f"zsk {lifetime['P30D']} 8 2048",
        f"zsk {lifetime['P6M']} 8 3072",
    ]
    keydir="keys"
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
