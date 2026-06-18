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
    names = ["test-a", "test-aaaa", "test-both"]
    for name in names:
        msg = isctest.query.create(name, "A")
        isctest.query.udp(msg, ns.ip)
    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    return isctest.text.TextFile(f"{ns.identifier}/named_dump.db")


def found(dump, txt):
    assert len(dump.grep(Re(txt))) == 1


def nfound(dump, txt):
    assert len(dump.grep(Re(txt))) == 0


def reconfig(ns, templates, disablev4, disablev6, dns64=False):
    templates.render(
        f"{ns.identifier}/named.conf",
        {"disablev4": disablev4, "disablev6": disablev6, "dns64": dns64},
    )
    with ns.watch_log_from_here() as watcher:
        ns.rndc("flush")
        watcher.wait_for_line("flushing caches in all views succeeded")
        ns.rndc("reconfig")
        watcher.wait_for_line("running")


def test_cache_delegns(ns2, templates):
    dump = query_and_dump(ns2)

    # By default the resoler has IPv4 and IPv6 dispatchers, so all
    # available glues are used and no server name is used.
    found(dump, "test-a. .* DELEG server-ipv4=10.10.10.10")
    found(dump, "test-aaaa. .* DELEG server-ipv6=acdc::acdc")
    found(dump, "test-both. .* DELEG server-ipv4=11.11.11.11 server-ipv6=ffac::dcff")
    nfound(dump, "test-a. .* DELEG server-name=.*")
    nfound(dump, "test-aaaa. .* DELEG server-name=.*")
    nfound(dump, "test-both. .* DELEG server-name=.*")

    reconfig(ns2, templates, disablev4=False, disablev6=True)
    dump = query_and_dump(ns2)

    # The resolver only has IPv4 dispatcher now, so it won't uses the
    # IPv6 glues (and uses the server name instead, if no IPv4 provided).
    found(dump, "test-a. .* DELEG server-ipv4=10.10.10.10")
    found(dump, "test-both. .* DELEG server-ipv4=11.11.11.11")
    nfound(dump, "test-a. .* DELEG server-name=.*")
    nfound(dump, "test-both. .* DELEG server-name=.*")

    # Nor IPv4 (not provided) nor IPv6 (provided but not used) nor NS name
    # (as no point storing it, we can't resolve it).
    nfound(dump, "test-aaaa. .* DELEG .*")

    reconfig(ns2, templates, disablev4=True, disablev6=False)
    dump = query_and_dump(ns2)

    # The resolver only has IPv6 dispatcher now, so it won't uses the
    # IPv4 glues (and uses the server name instead, if no IPv6 provided).
    nfound(dump, "test-a. .* DELEG server-ipv4=.*")
    found(dump, "test-aaaa. .* DELEG server-ipv6=acdc::acdc")
    found(dump, "test-both. .* DELEG server-ipv6=ffac::dcff")
    nfound(dump, "test-aaaa. .* DELEG server-name=.*")
    nfound(dump, "test-both. .* DELEG server-name=.*")

    # Nor IPv4 (provided by not used) nor IPv6 (not provided) nor NS name
    # (as no point storing it, we can't resolve it).
    nfound(dump, "test-a. .* DELEG .*")

    # This is now testing a specific case, where the resolver is IPv6 only
    # but uses resolver-use-dns64 to resolve IPv4 glues only. In this
    # specific case, the IPv4 glues must _still_ be added in the database.
    # So in practice, the result is the same as if both IPv4 and IPv6 are
    # enabled.
    reconfig(ns2, templates, disablev4=True, disablev6=False, dns64=True)
    dump = query_and_dump(ns2)

    found(dump, "test-a. .* DELEG server-ipv4=10.10.10.10")
    found(dump, "test-aaaa. .* DELEG server-ipv6=acdc::acdc")
    found(dump, "test-both. .* DELEG server-ipv4=11.11.11.11 server-ipv6=ffac::dcff")
    nfound(dump, "test-a. .* DELEG server-name=.*")
    nfound(dump, "test-aaaa. .* DELEG server-name=.*")
    nfound(dump, "test-both. .* DELEG server-name=.*")
