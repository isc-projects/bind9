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

from re import compile as Re


def test_configloading_log(ns1):
    """
    This test is a "guard/warning" to make sure the named.conf loading
    (parsing), keystore building, kasplist building and view creation is done
    outside of the exclusive mode (so, named is still able to answer queries
    and operating normally in case of configuration reload). It
    is currently based on logging, so it's quite brittle.
    """

    log_sequence = [
        "load_configuration",
        "parsing user configuration from ",
        "apply_configuration",
        "apply_configuration: configure_keystores",
        "apply_configuration: configure_kasplist",
        "apply_configuration: create_views",
        "loop exclusive mode: starting",
        "running",
    ]

    with ns1.watch_log_from_start() as watcher:
        watcher.wait_for_sequence(log_sequence)

    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reconfig")
        watcher.wait_for_sequence(log_sequence)

    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reload")
        watcher.wait_for_sequence(log_sequence)


def test_reload_fails_log(ns1, templates):
    """
    This test ensures that when a reconfig fails during view configuration (or
    after), views/zones (which are newly created view/zones which won't be used
    and local of apply_configuration) are detached (and freed) before the
    exclusive mode is released
    """

    log_sequence = [
        "apply_configuration",
        "loop exclusive mode: starting",
        "apply_configuration: configure_views",
        Re(r".*port '9999999' out of range"),
        "apply_configuration: detaching views",
        "loop exclusive mode: ending",
        "reloading configuration failed",
    ]

    with ns1.watch_log_from_here() as watcher:
        templates.render("ns1/named.conf", {"wrongoption": True})
        cmd = ns1.rndc("reload", raise_on_exception=False)
        assert cmd.rc != 0
        watcher.wait_for_sequence(log_sequence)
