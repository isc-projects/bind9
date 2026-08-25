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

# from dns.edns import EDECode
import pytest

from isctest.util import param

import isctest


def bootstrap():
    return {
        "many_anchors": True,
    }


@pytest.mark.parametrize(
    "zone, keytype, msg",
    [
        param("disabled.trusted.", "static-key", "algorithm is disabled"),
        param("disabled.managed.", "initial-key", "algorithm is disabled"),
        param("unsupported.trusted.", "static-key", "algorithm is unsupported"),
        param("unsupported.managed.", "initial-key", "algorithm is unsupported"),
        param("revoked.trusted.", "static-key", "bad key type"),
        param("revoked.managed.", "initial-key", "bad key type"),
    ],
)
def test_log_ignoring_key(zone, keytype, msg, ns5):
    with ns5.watch_log_from_start() as watcher:
        watcher.wait_for_line(f"ignoring {keytype} for '{zone}': {msg}")


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
    isctest.check.noede(res2)

    msg = isctest.query.create("a.secure.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)
    isctest.check.noede(res2)

    # check that an unsupported signing algorithm yields insecure
    msg = isctest.query.create("a.unsupported.trusted", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    # This EDE code should be added by the validator, but currently it isn't.
    # See issue #5832
    # isctest.check.ede(res2, EDECode.UNSUPPORTED_DNSKEY_ALGORITHM)
    isctest.check.noerror(res2)
    isctest.check.noadflag(res2)

    msg = isctest.query.create("a.unsupported.managed", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res1)
    # This EDE code should be added by the validator, but currently it isn't.
    # See issue #5832
    # isctest.check.ede(res2, EDECode.UNSUPPORTED_DNSKEY_ALGORITHM)
    print(res2)
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
