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

import isctest


def bootstrap():
    return {
        "multi_view": True,
    }


def getfrom(file):
    with open(file, encoding="utf-8") as f:
        return f.read().strip()


def test_staticstub_delegations():
    # check insecure delegation between static-stub zones
    def docheck():
        msg = isctest.query.create("insecure.secure.example", "NS")
        res = isctest.query.tcp(msg, "10.53.0.4")
        isctest.check.noerror(res)
        msg = isctest.query.create("secure.example", "NS")
        res = isctest.query.tcp(msg, "10.53.0.4")
        isctest.check.noerror(res)
        return True

    isctest.run.retry_with_timeout(docheck, 5)


def test_validator_logging(ns4):
    # check that validator logging includes the view name with multiple views
    pattern = Re("view rec: *validat")
    with ns4.watch_log_from_start() as watcher:
        msg = isctest.query.create("secure.example", "NS")
        isctest.query.tcp(msg, "10.53.0.4")
        watcher.wait_for_line(pattern)


def test_secure_roots(ns4, default_algorithm):
    # check that "rndc secroots" dumps the trusted keys with multiple views
    key = int(getfrom("ns1/managed.key.id"))
    response = ns4.rndc("secroots -")
    assert f"./{default_algorithm.name}/{key} ; static" in response.out
    assert len(response.out.splitlines()) == 17
