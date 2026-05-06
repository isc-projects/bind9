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


def test_cap_glues(ns3):
    msg = isctest.query.create("example.tld.", "A")
    isctest.query.udp(msg, ns3.ip)

    with ns3.watch_log_from_here() as watcher:
        ns3.rndc("dumpdb -deleg")
        watcher.wait_for_line("dumpdb complete")
    db = isctest.text.TextFile(f"{ns3.identifier}/named_dump.db")

    names_len = len(db.grep(Re("example.tld. ... DELEG server-name=")))
    if names_len == 12:
        # 12 NS names, 1 NS with glues (so no server-name), so 13 NS in total.
        allowed_suffixes = range(20, 40)
        skipped_suffixes = range(40, 44)
        assert len(db.grep(Re("example.tld. ... DELEG server-ipv4="))) == 1
        assert (
            len(db.grep(Re("example.tld. ... DELEG server-ipv4=.* server-ipv6="))) == 1
        )

        for n in allowed_suffixes:
            assert len(db.grep(f"10.53.0.{n}")) == 1
            assert len(db.grep(f"2001:db8::{n}")) == 1

        for n in skipped_suffixes:
            assert len(db.grep(f"10.53.0.{n}")) == 0
            assert len(db.grep(f"2001:db8::{n}")) == 0
    else:
        # 13 NS names and no glues. This occurs if the 13 NS without glues
        # has been processed first.
        assert names_len == 13
        assert len(db.grep(Re("example.tld. ... DELEG server-ipv4="))) == 0
        assert len(db.grep(Re("example.tld. ... DELEG server-ipv6="))) == 0
