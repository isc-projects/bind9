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

import pytest

import isctest


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns5, templates):
    templates.render("ns5/named.conf", {"revoked_key": True})
    ns5.reconfigure(log=False)


def test_revoked_init():
    # use a revoked key and check for failure when using revoked key
    msg = isctest.query.create(".", "SOA")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)
