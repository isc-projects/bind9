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

from dns import rdatatype

import pytest

import isctest


@pytest.mark.parametrize(
    "name, dnssec, expect_rrsig",
    [
        ("a.test", True, True),
        ("a.test", False, False),
        ("b.test", True, False),
        ("b.test", False, False),
    ],
)
def test_rrsig(name, dnssec, expect_rrsig):
    msg = isctest.query.create(name, "A", dnssec=dnssec)
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    if expect_rrsig:
        assert len(res.answer) == 2
        assert res.answer[1].rdtype == rdatatype.RRSIG
    else:
        assert len(res.answer) == 1
    assert res.answer[0].rdtype == rdatatype.A
