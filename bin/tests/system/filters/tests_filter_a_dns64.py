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

import pytest

from filters.common import ARTIFACTS

import isctest

pytestmark = pytest.mark.extra_artifacts(ARTIFACTS)


def bootstrap():
    return {
        "family": "v4",
        "filtertype": "a",
    }


def test_dns64_filter_a_reentry(ns5):
    msg = isctest.query.create("nodata.test.", "aaaa", dnssec=False)
    with ns5.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns5.ip, attempts=1)

        # ans6 holds the A answer back until the NODATA has expired from the
        # cache, so filter-a has to query AAAA again; without that, the bug
        # is not exercised at all
        watcher.wait_for_sequence(
            [
                Re(r"fetch: nodata\.test/AAAA$"),
                Re(r"fetch: nodata\.test/A$"),
                Re(r"fetch: nodata\.test/AAAA$"),
            ]
        )

    isctest.check.noerror(res)
    answer = res.get_rrset(res.answer, "nodata.test.", "in", "aaaa")
    assert answer is not None, res
    assert answer[0].address == "64:ff9b::c000:201"
