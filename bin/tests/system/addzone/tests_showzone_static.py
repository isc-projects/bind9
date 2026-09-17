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

import pytest


# Test that `rndc showzone` can print any zone, including those statically
# defined in named.conf, and not only those added dynamically.
@pytest.mark.parametrize(
    "allow",
    [
        pytest.param(True, id="allow-new-zones-yes"),
        pytest.param(False, id="allow-new-zones-no"),
    ],
)
def test_showzone_static(ns1, templates, allow):
    templates.render("ns1/named.conf", {"allownewzones": allow})
    ns1.rndc("reload")
    response = ns1.rndc("showzone inlinesec.example")
    assert (
        'zone "inlinesec.example" { type primary; file "inlinesec.db"; };'
        in response.out
    )
