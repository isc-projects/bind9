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


def test_two_zone_files_with_the_same_origin_are_refused(ans1):
    with ans1.watch_log_from_start() as watcher:
        watcher.wait_for_line('zone "." is defined by more than one zone file')
    # The server died as intended; keep stop.pl from reporting it at teardown.
    (ans1.directory / "ans.pid").unlink()
