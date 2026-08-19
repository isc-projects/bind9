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

import dns.message

import isctest


# The root server (ns1) serves a root zone whose NS has no address
# record, so the priming response carries the root NS answer but no
# glue in the ADDITIONAL section.  The resolver (ns2) then cannot
# build a delegation set from it and the whole priming fetch is failing.
def test_priming_response_without_glue(ns2):
    msg = dns.message.make_query(".", "NS")
    with ns2.watch_log_from_here() as watcher:
        res = isctest.query.udp(msg, ns2.ip)
        watcher.wait_for_sequence(
            [
                "missing mandatory glue for a.root-servers.nil",
                "resolver priming query complete: SERVFAIL",
            ]
        )
    isctest.check.noerror(res)


def dump_delegdb(ns):
    with ns.watch_log_from_here() as watcher:
        ns.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    return isctest.text.TextFile(f"{ns.identifier}/named_dump.db")


# A root hints file is allowed to use $INCLUDE.
def test_priming_hints_include(ns2, templates):
    templates.render("ns2/named.conf", {"hintfile": "root-include.hint"})
    ns2.reload()

    dump = dump_delegdb(ns2)
    assert dump.grep("DELEG server-ipv4=10.53.0.1")


# A hints file that fails to load halfway (with some glue already
# parsed) must fail the reload and must not overwrite the live root
# hints in the delegation cache.
def test_priming_hints_broken(ns2, templates):
    templates.render("ns2/named.conf", {"hintfile": "root-broken.hint"})
    with ns2.watch_log_from_here() as watcher:
        cmd = ns2.rndc("reload", raise_on_exception=False)
        assert cmd.rc != 0
        watcher.wait_for_line("could not configure root hints")

    dump = dump_delegdb(ns2)
    assert dump.grep("DELEG server-ipv4=10.53.0.1")
    assert not dump.grep("10.53.0.99")
