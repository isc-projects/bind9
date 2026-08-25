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

import shutil


def test_views_add_zones(ns2, templates):
    zone_names = []
    for i in range(50):
        name = f"example{i:03}.com"
        zone_names.append(name)
        templates.render(
            "ns2/named.conf", {"zone_names": zone_names}, template="ns2/named3.conf.j2"
        )
        shutil.copyfile("ns2/zone.db.in", f"ns2/{name}.db")
        with ns2.watch_log_from_here() as watcher:
            ns2.rndc("reconfig")
            log_seq = ["any newly configured zones are now loaded", "running"]
            watcher.wait_for_sequence(log_seq)
