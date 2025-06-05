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

import pytest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns1/managed-keys.bind.jnl",
    ]
)


def assert_log_sequence(server, fnname, scopefn):
    triggers = {
        "load_configuration": 0,
        "parsing user configuration from ": 1,
        "apply_configuration": 2,
        "loop exclusive mode: starting": 3,
    }
    fn = getattr(server, fnname)
    for i in range(len(triggers.items())):
        with fn() as watcher:
            scopefn()
            assert watcher.wait_for_lines(dict(list(triggers.items())[i:])) == i


def test_configloading_loading(servers):
    server = servers["ns1"]
    assert_log_sequence(server, "watch_log_from_start", lambda: ())


def test_configloading_reconfig(servers):
    server = servers["ns1"]
    assert_log_sequence(server, "watch_log_from_here", lambda: server.rndc("reconfig"))


def test_configloading_reload(servers):
    server = servers["ns1"]
    assert_log_sequence(server, "watch_log_from_here", lambda: server.rndc("reload"))
