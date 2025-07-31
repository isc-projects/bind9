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

from dns import flags

import pytest

import isctest
from isctest.util import param


pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.bk",
        "*/*.conf",
        "*/*.db",
        "*/*.id",
        "*/*.jnl",
        "*/*.jbk",
        "*/*.key",
        "*/*.signed",
        "*/settime.out.*",
        "ans*/ans.run",
        "*/trusted.keys",
        "*/*.bad",
        "*/*.next",
        "*/*.stripped",
        "*/*.tmp",
        "*/*.stage?",
        "*/*.patched",
        "*/*.lower",
        "*/*.upper",
        "*/*.unsplit",
    ]
)


@pytest.mark.parametrize(
    "check, qname, qtype",
    [
        param("validation", "example.", "SOA"),
        param("negative-validation", "example.", "PTR"),
        param("insecurity-proof", "a.insecure.example.", "A"),
    ],
)
def test_misconfigured_ta_servfail(check, qname, qtype):
    isctest.log.info(f"check that {check} fails")
    msg = isctest.query.create(qname, qtype)
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)


@pytest.mark.parametrize(
    "check, qname, qtype, rcode_func",
    [
        param("positive-answer", "example.", "SOA", isctest.check.noerror),
        param("negative-answer", "q.example.", "SOA", isctest.check.nxdomain),
        param("bogus-answer", "a.bogus.example.", "SOA", isctest.check.noerror),
        param("insecurity-proof", "a.insecure.example.", "SOA", isctest.check.noerror),
        param(
            "negative-insecurity-proof",
            "q.insecure.example.",
            "SOA",
            isctest.check.nxdomain,
        ),
    ],
)
def test_misconfigured_ta_with_cd(check, qname, qtype, rcode_func):
    isctest.log.info(f"check {check} with CD=1")
    msg = isctest.query.create(qname, qtype)
    msg.flags |= flags.CD
    res = isctest.query.tcp(msg, "10.53.0.5")
    rcode_func(res)
    isctest.check.noadflag(res)

    isctest.log.debug("compare the response from a correctly configured server")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noadflag(res2)
    isctest.check.same_answer(res, res2)
