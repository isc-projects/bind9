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


# XML helper functions
def fetch_xml(statsip, statsport):
    import xml.etree.ElementTree as ET
    import requests

    r = requests.get("http://{}:{}/xml/v3/zones".format(statsip, statsport))
    assert r.status_code == 200

    root = ET.fromstring(r.text)

    default_view = None
    for view in root.find('views').iter('view'):
        if view.attrib['name'] == "_default":
            default_view = view
            break
    assert default_view is not None

    return default_view.find('zones').findall('zone')


def load_timers_from_xml(zone, primary=True):
    name = zone.attrib['name']

    loaded_el = zone.find('loaded')
    assert loaded_el is not None
    loaded = datetime.strptime(loaded_el.text, fmt)

    expires_el = zone.find('expires')
    refresh_el = zone.find('refresh')
    if primary:
        assert expires_el is None
        assert refresh_el is None
        expires = None
        refresh = None
    else:
        assert expires_el is not None
        assert refresh_el is not None
        expires = datetime.strptime(expires_el.text, fmt)
        refresh = datetime.strptime(refresh_el.text, fmt)

    return (name, loaded, expires, refresh)


@pytest.mark.xml
@pytest.mark.requests
def test_zone_timers_primary_xml(statsport):
    statsip = "10.53.0.1"
    zonedir = "ns1"

    zones = fetch_xml(statsip, statsport)

    for zone in zones:
        (name, loaded, expires, refresh) = load_timers_from_xml(zone, True)
        mtime = zone_mtime(zonedir, name)
        check_zone_timers(loaded, expires, refresh, mtime)


@pytest.mark.xml
@pytest.mark.requests
def test_zone_timers_secondary_xml(statsport):
    statsip = "10.53.0.3"

    zones = fetch_xml(statsip, statsport)

    for zone in zones:
        (name, loaded, expires, refresh) = load_timers_from_xml(zone, False)
        check_zone_timers(loaded, expires, refresh, dayzero)
