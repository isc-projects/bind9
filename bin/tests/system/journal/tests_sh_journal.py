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


def bootstrap():
    # ns1's managed-keys journal is a hand-crafted old-format specimen,
    # committed as a hex dump
    hex_dump = Path("ns1/managed-keys.bind.jnl.in").read_text(encoding="utf-8")
    Path("ns1/managed-keys.bind.jnl").write_bytes(bytes.fromhex(hex_dump))


def test_journal(run_tests_sh):
    run_tests_sh()
