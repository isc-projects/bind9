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

import requests

import isctest
import isctest.mark

pytestmark = [isctest.mark.live_internet_test]

# URL for the official root hints file
NAMED_ROOT_URL = "https://www.internic.net/zones/named.root"


def normalize_text(text):
    """Omit lines we don't want to compare"""
    skip_starts_with = (
        ";       last update:",
        ";       related version of root zone:",
    )
    normalized = []
    for line in text.splitlines():
        if line.startswith(skip_starts_with):
            continue
        normalized.append(line)
    return normalized


def test_named_root_hints():
    """
    Test that 'named -H' output matches the official
    root hints from https://www.internic.net/zones/named.root
    """
    resp = requests.get(NAMED_ROOT_URL, timeout=30)
    resp.raise_for_status()

    internic = normalize_text(resp.text)

    named = isctest.vars.ALL["NAMED"]
    cmd = isctest.run.cmd([named, "-H"])
    builtin = normalize_text(cmd.out)

    assert internic == builtin, "Built-in root hints differ from official named.root"
