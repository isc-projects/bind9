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

from dns import edns
import pytest

import isctest


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns5, templates):
    templates.render("ns5/named.conf", {"many_anchors": True})
    with ns5.watch_log_from_here() as watcher:
        ns5.reconfigure(log=False)
        watcher.wait_for_line(
            [
                "ignoring static-key for 'disabled.trusted.': algorithm is disabled",
                "ignoring static-key for 'disabled.managed.': algorithm is disabled",
                "ignoring static-key for 'unsupported.trusted.': algorithm is unsupported",
                "ignoring static-key for 'unsupported.managed.': algorithm is unsupported",
                "ignoring static-key for 'unsupported.managed.': algorithm is unsupported",
                "ignoring static-key for 'revoked.trusted.': bad key type",
                "ignoring static-key for 'revoked.managed.': bad key type",
            ]
        )


def test_trust_anchors():
    # DNSSEC tests related to unsupported, disabled and revoked trust anchors.
    #
    # This nameserver is loaded with a bunch of trust anchors.
    # Some of them are good (enabled.managed, enabled.trusted,
    # secure.managed, secure.trusted), and some of them are bad
    # (disabled.managed, revoked.managed, unsupported.managed,
    # disabled.trusted, revoked.trusted, unsupported.trusted).  Make sure
    # that the bad trust anchors are ignored.  This is tested by looking
    # for the corresponding lines in the logfile.

    # check that a key with supported algorithm validates as secure
    msg = isctest.query.create("a.secure.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    if hasattr(res2, "extended_errors"):
        assert not res2.extended_errors()

    msg = isctest.query.create("a.secure.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    if hasattr(res2, "extended_errors"):
        assert not res2.extended_errors()

    # check that an unsupported signing algorithm yields insecure
    msg = isctest.query.create("a.unsupported.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    if hasattr(res2, "extended_errors"):
        assert (
            res2.extended_errors()[0].code == edns.EDECode.UNSUPPORTED_DNSKEY_ALGORITHM
        )
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    msg = isctest.query.create("a.unsupported.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    if hasattr(res2, "extended_errors"):
        assert (
            res2.extended_errors()[0].code == edns.EDECode.UNSUPPORTED_DNSKEY_ALGORITHM
        )
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # check that a disabled signing algorithm yields insecure
    msg = isctest.query.create("a.disabled.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    msg = isctest.query.create("a.disabled.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    # check that zone signed with an algorithm that's disabled for
    # some other domain, but not for this one, validates as secure.
    # "enabled.trusted." and "enabled.managed." do not match the
    # "disable-algorithms" option, so no special rules apply. (static)
    msg = isctest.query.create("a.enabled.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)

    msg = isctest.query.create("a.enabled.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)

    # a revoked trust anchor is ignored when configured; check that
    # this yields insecure.
    msg = isctest.query.create("a.revoked.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    msg = isctest.query.create("a.revoked.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)
