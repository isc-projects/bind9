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

import isctest


def test_forward_only_deleg(ns4):
    msg = isctest.query.create("a.foo.fwdonly.", "A")
    res = isctest.query.udp(msg, ns4.ip)
    isctest.check.servfail(res)
