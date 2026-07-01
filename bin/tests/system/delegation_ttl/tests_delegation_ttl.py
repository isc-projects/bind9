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

from re import compile as Re

import isctest


def found(cache, pattern):
    assert len(cache.grep(Re(pattern))) == 1


def warm_get_cache(ns):
    with ns.watch_log_from_here() as watcher:
        ns.rndc("flush")
        ns.rndc("reload")
        watcher.wait_for_sequence(
            [
                "flushing caches in all views succeeded",
                "loop exclusive mode: ended",
                "running",
            ]
        )

    msg = isctest.query.create("ns.tld-10.", "A")
    isctest.query.udp(msg, ns.ip)
    msg = isctest.query.create("ns.tld-50.", "A")
    isctest.query.udp(msg, ns.ip)
    msg = isctest.query.create("ns.tld-100.", "A")
    isctest.query.udp(msg, ns.ip)

    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    return isctest.text.TextFile(f"{ns.identifier}/named_dump.db")


def test_delegation_ttl_default(ns2):
    cache = warm_get_cache(ns2)
    found(cache, "tld-10\\. (60|5[0-9]) DELEG server-ipv4=")
    found(cache, "tld-50\\. (60|5[0-9]) DELEG server-ipv4=")
    found(cache, "tld-100\\. (100|9[0-9]) DELEG server-ipv4=")


def test_delegation_min_ttl_40_60(ns2, templates):
    templates.render("ns2/named.conf", {"minttl": 40, "maxttl": 60})
    cache = warm_get_cache(ns2)
    found(cache, "tld-10\\. (40|3[0-9]) DELEG server-ipv4=")
    found(cache, "tld-50\\. (50|4[0-9]) DELEG server-ipv4=")
    found(cache, "tld-100\\. (60|5[0-9]) DELEG server-ipv4=")


def test_delegation_min_ttl_disabled(ns2, templates):
    templates.render("ns2/named.conf", {"minttl": 0, "maxttl": 0})
    cache = warm_get_cache(ns2)
    found(cache, "tld-10\\. (10|[1-9]) DELEG server-ipv4=")
    found(cache, "tld-50\\. (50|4[0-9]) DELEG server-ipv4=")
    found(cache, "tld-100\\. (100|9[0-9]) DELEG server-ipv4=")


def check_ttl_error(ns):
    with ns.watch_log_from_here() as watcher:
        cmd = ns.rndc("reload", raise_on_exception=False)
        assert cmd.rc != 0
        watcher.wait_for_line(
            "When 'min-delegation-ttl' and 'max-delegation-ttl' are both positive, 'min-delegation-ttl' must be strictly less than 'max-delegation-ttl'"
        )


def test_delegdb_ttl_default_5(ns2, templates):
    templates.render("ns2/named.conf", {"maxttl": 5})
    check_ttl_error(ns2)


def test_delegdb_ttl_10_5(ns2, templates):
    templates.render("ns2/named.conf", {"minttl": 10, "maxttl": 5})
    check_ttl_error(ns2)
