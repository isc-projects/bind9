#!/usr/bin/python3
############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

import pytest
from datetime import datetime
from helper import fmt, zone_mtime, check_zone_timers, dayzero


# JSON helper functions
def fetch_json(statsip, statsport):
    import requests

    r = requests.get("http://{}:{}/json/v1/zones".format(statsip, statsport))
    assert r.status_code == 200

    data = r.json()

    return data["views"]["_default"]["zones"]


def load_timers_from_json(zone, primary=True):
    name = zone['name']

    # Check if the primary zone timer exists
    assert 'loaded' in zone
    loaded = datetime.strptime(zone['loaded'], fmt)

    if primary:
        # Check if the secondary zone timers does not exist
        assert 'expires' not in zone
        assert 'refresh' not in zone
        expires = None
        refresh = None
    else:
        assert 'expires' in zone
        assert 'refresh' in zone
        expires = datetime.strptime(zone['expires'], fmt)
        refresh = datetime.strptime(zone['refresh'], fmt)

    return (name, loaded, expires, refresh)


@pytest.mark.json
@pytest.mark.requests
def test_zone_timers_primary_json(statsport):
    statsip = "10.53.0.1"
    zonedir = "ns1"

    zones = fetch_json(statsip, statsport)

    for zone in zones:
        (name, loaded, expires, refresh) = load_timers_from_json(zone, True)
        mtime = zone_mtime(zonedir, name)
        check_zone_timers(loaded, expires, refresh, mtime)


@pytest.mark.json
@pytest.mark.requests
def test_zone_timers_secondary_json(statsport):
    statsip = "10.53.0.3"

    zones = fetch_json(statsip, statsport)

    for zone in zones:
        (name, loaded, expires, refresh) = load_timers_from_json(zone, False)
        check_zone_timers(loaded, expires, refresh, dayzero)
