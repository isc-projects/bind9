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

import time

from dns.edns import EDECode

import isctest


def check_sfcache_ede(ns, ede):
    msg = isctest.query.create("foo.example.", "A")
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.servfail(res)
    if ede:
        # The SERVFAIL is cached, so now it shows up the EDE CACHED_ERROR, but not the DNSKEY_MISSING.
        isctest.check.ede(res, EDECode.CACHED_ERROR)
    else:
        # example. domain DNSSEC is misconfigured on ns2, as it have two ZSK but no KSK. As a result, the DNSKEY for example. can't be found.
        isctest.check.ede(res, EDECode.DNSKEY_MISSING)


def test_sfcache_ede(ns5, templates):
    # Reconfigure the server so servfail-ttl is 1 second
    templates.render("ns5/named.conf", {"servfail_ttl": 1})
    with ns5.watch_log_from_here() as watcher:
        ns5.rndc("reload")
        watcher.wait_for_line("running")

    # First query do not have a cached SERVFAIL, no EDE
    check_sfcache_ede(ns5, False)

    # Immediates next queries are cached SERVFAIL, EDE present
    check_sfcache_ede(ns5, True)
    check_sfcache_ede(ns5, True)

    # Wait enough time so we know he cached SERVFAIL is removed
    time.sleep(2)

    # And again, first query is not cached, subsequent ones are.
    check_sfcache_ede(ns5, False)
    check_sfcache_ede(ns5, True)
    check_sfcache_ede(ns5, True)
