# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

"""
DELEG server names whose text form needs escaping.
"""

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(["ns1/example.db", "ns1/named_dump.db"])

# Three labels of 63 commas: in the DELEG text syntax a comma inside a
# server name is written as "\\,", so the text form is three times as
# long as the wire form.
COMMA_LABEL = "\\\\," * 63
COMMA_NAME = ".".join([COMMA_LABEL] * 3) + "."
NAMES = ",".join([COMMA_NAME] * 3)


def bootstrap():
    return {"deleg": f"server-name={NAMES}"}


@pytest.mark.requires_zones_loaded("ns1")
def test_dumpdb_escaped_server_names(ns1):
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("dumpdb -zones")
        watcher.wait_for_line("dumpdb complete")

    assert f"server-name={NAMES}" in isctest.text.TextFile("ns1/named_dump.db")


def test_overlong_server_name_in_zone_file(ns1, templates):
    # A single server name item longer than 255 bytes is rejected, and
    # a doubled backslash right at the 255-byte mark must not change that.
    item = "a" * 255 + "\\\\\\\\" + "a" * 2000
    templates.render("ns1/example.db", {"deleg": f"server-name={item}"}, newer=True)
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reload example")
        watcher.wait_for_line(
            "zone example/IN: loading from master file example.db failed"
        )
