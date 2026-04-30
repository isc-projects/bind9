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


def query_and_dump(ns):
    msg = isctest.query.create("a.foo.test.", "A")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.noerror(res)

    msg = isctest.query.create("a.bar.test.", "A")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.noerror(res)

    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    return isctest.text.TextFile(f"{ns.identifier}/named_dump.db")


def test_cyclic_glues(ns1, ns4, templates):
    dump = query_and_dump(ns4)

    # The test is using the correctly-behaving ns2 server.
    assert len(dump.grep(Re("test. .* DELEG server-ipv4=10.53.0.2"))) == 1
    assert len(dump.grep(Re("test. .* DELEG server-ipv4=10.53.0.5"))) == 0

    # We've sent queries for both foo.test and bar.test and got a
    # single in-domain address from each:
    assert len(dump.grep(Re("foo.test. [0-9]* DELEG server-ipv4=10.53.0.3"))) == 1
    assert len(dump.grep(Re("foo.test. [0-9]* DELEG"))) == 1

    assert len(dump.grep(Re("bar.test. [0-9]* DELEG server-ipv4=10.53.0.3"))) == 1
    assert len(dump.grep(Re("bar.test. [0-9]* DELEG"))) == 1

    # in total we should have test, foo.test, and bar.test, nothing else:
    assert len(dump.grep(Re("test. [0-9]* DELEG"))) == 3

    templates.render("ns1/root.db", {"broken_ns": True})
    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("reload")
        watcher.wait_for_line("running")

    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("flush")
        watcher.wait_for_line("flushing caches in all views succeeded")

    dump = query_and_dump(ns4)

    # The test is now using the broken ans5 server.
    assert len(dump.grep(Re("test. [0-9]* DELEG server-ipv4=10.53.0.2"))) == 0
    assert len(dump.grep(Re("test. [0-9]* DELEG server-ipv4=10.53.0.5"))) == 1

    # The bar and foo delegations include names and glue records
    # that are out of bailiwick; we need to ensure that we are not
    # using the address, but only its name.
    assert len(dump.grep(Re("10.10.10.10"))) == 0
    assert len(dump.grep(Re("test2. "))) == 0
    assert len(dump.grep(Re("foo.test. [0-9]* DELEG server-name=ns.test2."))) == 1

    # There should in principle be only one of these, but there is no guard
    # to prevent duplicates when two glues for two different owner names
    # (in this case, ns.foo.test and ns.bar.test) both point to the same
    # IP address.
    assert len(dump.grep(Re("foo.test. [0-9]* DELEG server-ipv4="))) > 0

    # ns.bar.test is in-domain and should be stored as an address,
    # not a server-name.
    assert len(dump.grep(Re("bar.test. [0-9]* DELEG server-name=ns.bar.test."))) == 0
    assert len(dump.grep(Re("bar.test. [0-9]* DELEG server-ipv4=10.53.0.3"))) == 1

    # Since ns2.foo.test. came from the same parent (sibling glue) we have
    # its address, NOT its server-name.
    assert len(dump.grep(Re("bar.test. [0-9]* DELEG server-name=ns2.foo.test."))) == 0
    assert len(dump.grep(Re("bar.test. [0-9]* DELEG server-ipv4=10.53.0.4"))) == 1
