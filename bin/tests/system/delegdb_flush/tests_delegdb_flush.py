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

import requests

import isctest.mark

pytestmark = [isctest.mark.with_json_c, isctest.mark.with_developer]


def get_delegdb_watermarks(ip, port):
    watermarks = []
    r = requests.get(f"http://{ip}:{port}/json/v1/mem", timeout=600)
    assert r.status_code == 200
    mem = r.json()["memory"]
    for c in mem["contexts"]:
        if c["name"] == "dns_delegdb":
            watermarks.append((c["id"], c["lowater"], c["hiwater"]))
    return watermarks


def check_watermarks(watermarks1, watermarks2):
    if watermarks2 is not None:
        assert len(watermarks1) == len(watermarks2)
    for i, (id1, lowater1, hiwater1) in enumerate(watermarks1):
        assert lowater1 > 0
        assert hiwater1 > 0
        if watermarks2 is not None:
            id2, lowater2, hiwater2 = watermarks2[i]
            assert id1 != id2
            assert lowater1 == lowater2
            assert hiwater1 == hiwater2


def test_delegdb_flush(ns1):
    statsport = os.getenv("EXTRAPORT1")

    watermarks1 = get_delegdb_watermarks(ns1.ip, statsport)
    check_watermarks(watermarks1, None)

    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("flush")
        watcher.wait_for_sequence(
            ["flushing caches in all views succeeded", "loop exclusive mode: ended"]
        )

    # The previous delegdb contexts can still be hanging around for a little
    # bit, until RCU reclamation run and it actually gets detached/freed.
    for watermarks in watermarks1:
        id1, _, _ = watermarks
        with ns1.watch_log_from_start() as watcher:
            watcher.wait_for_line(f"destroyed mctx {id1}")

    watermarks2 = get_delegdb_watermarks(ns1.ip, statsport)
    check_watermarks(watermarks1, watermarks2)
