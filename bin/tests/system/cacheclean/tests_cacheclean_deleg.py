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

import time

import isctest

DUMP_FILE_NAME = "ns2/named_dump.db"


def warmup_cache(ns):
    # Let's flush all caches first so we're sure the query will fully run into the resolver.
    flush_caches(ns, "flush", "", "flushing caches in all views succeeded")
    msg = isctest.query.create("gee.foo.bar.com.", "A")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.noerror(res)
    msg = isctest.query.create("whatever.lame-and-expired-soon.bar.com.", "A")
    # This will fail, we don't care, this is just to have the entry in the cache
    isctest.query.udp(msg, ns.ip)
    assert len(res.answer) == 1


def check_cache_expired(ns):
    time.sleep(2)
    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -expired")
        watcher.wait_for_line("dumpdb complete")
    with isctest.log.WatchLogFromStart(DUMP_FILE_NAME) as watcher:
        patterns = [
            Re("lame-and-expired-soon.bar.com. 0 DELEG server-name=ns.somehost.com."),
            Re("foo.bar.com. 99999[5-9] DELEG server-name=ns.somehost.com."),
        ]
        watcher.wait_for_all(patterns)


def check_cache(ns, hit):
    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    with isctest.log.WatchLogFromStart(DUMP_FILE_NAME) as watcher:
        if hit:
            pattern = Re("foo.bar.com. 99999[5-9] DELEG server-name=ns.somehost.com.")
            watcher.wait_for_line(pattern)
        else:
            seq = ["; Delegation cache", ";", ";", "; Start view _bind"]
            watcher.wait_for_sequence(seq)


def reload_server(ns):
    with ns.watch_log_from_here() as watcher:
        ns.rndc("reload")
        watcher.wait_for_line("running")
    with ns.watch_log_from_here() as watcher:
        ns.rndc("reconfig")
        watcher.wait_for_line("running")


def flush_caches(ns, flushcmd, flusharg, confirm):
    with ns.watch_log_from_here() as watcher:
        ns.rndc(f"{flushcmd} {flusharg}")
        watcher.wait_for_line(confirm)


def test_cacheclean_deleg(ns2):
    # Make sure the delegation cache has foo.bar.com.
    warmup_cache(ns2)

    # Flushing the cache
    check_cache(ns2, True)

    # Reloading the server keeps the cache hot
    reload_server(ns2)

    # The cache is still hot
    check_cache(ns2, True)

    # Flush the cache, and its now cold
    flush_caches(ns2, "flush", "", "flushing caches in all views succeeded")
    check_cache(ns2, False)

    # Flush just the name foo.bar.com.
    warmup_cache(ns2)
    check_cache(ns2, True)
    flush_caches(
        ns2,
        "flushname",
        "foo.bar.com.",
        "flushing name 'foo.bar.com.' in delegation cache for all views succeeded",
    )
    check_cache(ns2, False)

    # Flush the whole .com. tree (need to flush
    warmup_cache(ns2)
    check_cache(ns2, True)
    flush_caches(
        ns2,
        "flushtree",
        "com.",
        "flushing tree 'com.' in DNS cache for all views succeeded",
    )
    check_cache(ns2, False)

    # Check -expired
    warmup_cache(ns2)
    check_cache(ns2, True)
    check_cache_expired(ns2)
