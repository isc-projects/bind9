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

from pathlib import Path

import shutil

import pytest

pytestmark = pytest.mark.extra_artifacts(
    [
        "dig.out.*",
        "journalprint.out.*",
        "makejournal.out.*",
        "tmp.jnl",
        "ns*/*.db",
        "ns*/*.jnl",
        "ns1/managed-keys.bind",
        "ns2/managed-keys.bind",
        "zones/*.jnl",
    ]
)

# Working copies of the committed fixtures: named modifies the zone files
# and journals, so each zone gets its own copy of the generic zone data
# and of the appropriate pre-cooked journal.
SETUP_COPIES = [
    ("ns1/generic.db.in", "ns1/changed.db"),
    ("ns1/changed.ver1.jnl.saved", "ns1/changed.db.jnl"),
    ("ns1/generic.db.in", "ns1/unchanged.db"),
    ("ns1/unchanged.ver1.jnl.saved", "ns1/unchanged.db.jnl"),
    ("ns1/generic.db.in", "ns1/changed2.db"),
    ("ns1/changed.ver2.jnl.saved", "ns1/changed2.db.jnl"),
    ("ns1/generic.db.in", "ns1/unchanged2.db"),
    ("ns1/unchanged.ver2.jnl.saved", "ns1/unchanged2.db.jnl"),
    ("ns1/ixfr.db.in", "ns1/ixfr.db"),
    ("ns1/ixfr.ver1.jnl.saved", "ns1/ixfr.db.jnl"),
    ("ns1/generic.db.in", "ns1/d1212.db"),
    ("ns1/d1212.jnl.saved", "ns1/d1212.db.jnl"),
    ("ns1/generic.db.in", "ns1/d2121.db"),
    ("ns1/d2121.jnl.saved", "ns1/d2121.db.jnl"),
    ("ns1/generic.db.in", "ns1/maxjournal.db"),
    ("ns1/maxjournal.jnl.saved", "ns1/maxjournal.db.jnl"),
    ("ns1/generic.db.in", "ns1/maxjournal2.db"),
    ("ns1/maxjournal2.jnl.saved", "ns1/maxjournal2.db.jnl"),
    ("ns1/managed-keys.bind.in", "ns1/managed-keys.bind"),
    ("ns2/managed-keys.bind.in", "ns2/managed-keys.bind"),
    ("ns2/managed-keys.bind.jnl.in", "ns2/managed-keys.bind.jnl"),
]


def bootstrap():
    for src, dst in SETUP_COPIES:
        shutil.copyfile(src, dst)

    # ns1's managed-keys journal is a hand-crafted old-format specimen,
    # committed as a hex dump
    hex_dump = Path("ns1/managed-keys.bind.jnl.in").read_text(encoding="utf-8")
    Path("ns1/managed-keys.bind.jnl").write_bytes(bytes.fromhex(hex_dump))


def test_journal(run_tests_sh):
    run_tests_sh()
