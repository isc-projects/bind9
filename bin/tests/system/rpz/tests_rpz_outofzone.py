#!/usr/bin/python3

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

from isctest.instance import NamedInstance


def test_rpz_out_of_zone_owner_name(ns3: NamedInstance) -> None:
    """
    ns3's "outofzone.tld2." policy zone is pre-seeded with a backup file
    holding a "com." record, whose two labels are fewer than the three of
    the origin that gets stripped from an owner name to build the trigger
    name.  Such a record used to underflow an unsigned label count in the
    RPZ code and fail an assertion, taking named down as the policy zone
    was loaded.  The zone database now refuses to load out-of-zone data
    altogether, so the record can no longer get anywhere near the RPZ
    code - reaching this test at all is most of the check.
    """
    assert (
        "zone outofzone.tld2/IN: loading from master file outofzone.db "
        "failed: out-of-zone data" in ns3.log
    )
