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


def test_named_root_hints():
    """
    Test that 'named -H' output matches the official
    root hints from https://www.internic.net/zones/named.root
    """
    resp = requests.get(NAMED_ROOT_URL, timeout=30)
    resp.raise_for_status()

    # the last line misses newline character, named ensures all lines have posix ends
    internic_content = resp.text + "\n"

    named = isctest.vars.ALL["NAMED"]
    cmd = isctest.run.cmd([named, "-H"])
    builtin_content = cmd.out

    assert (
        internic_content == builtin_content
    ), "Built-in root hints differ from official named.root"
