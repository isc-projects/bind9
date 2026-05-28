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

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/*.nzf*",
        "ns*/*.nzd*",
        "ns1/redirect.db",
        "ns2/new-zones",
        "ns2/redirect.db",
        "ns3/redirect.db",
    ]
)


def test_rndc_addzone_bad_template(ns2):
    """
    Confirm "rndc addzone" fails for a zone that refers to a badly configured template.
    """
    zone = "badtemplate.example"
    cmd = ns2.rndc(
        "addzone badtemplate.example {template bad;};",
        raise_on_exception=False,
    )
    assert cmd.rc == 1

    assert "'max-retry-time' must not be zero" in ns2.log
    assert "'min-retry-time' must not be zero" in ns2.log
    assert "'max-refresh-time' must not be zero" in ns2.log
    assert "'min-refresh-time' must not be zero" in ns2.log

    # Confirm that the addzone failed to add the zone
    cmd = ns2.rndc(f"showzone {zone}", raise_on_exception=False)
    assert cmd.rc == 1
    assert f"no matching zone '{zone}' in any view" in cmd.err
