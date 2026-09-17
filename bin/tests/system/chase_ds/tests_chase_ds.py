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

import isctest


def test_chase_ds(ns3):
    msg = isctest.query.create("a.example.", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    # Wait for example./DS and example./DNSKEY to expire
    time.sleep(5)

    msg = isctest.query.create("a.example.", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    # The validator `get_dsset()` function found example. parent NS
    # (which is./NS) using `dns_view_bestzonecut()`, so there is no
    # need to chase the DS starting form `example./NS`).
    prohibited_log = "chase DS servers resolving 'example/DS/IN'"
    assert prohibited_log not in ns3.log

    prohibited_log = "suspending DS lookup to find parent's NS records"
    assert prohibited_log not in ns3.log
