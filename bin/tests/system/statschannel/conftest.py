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
import os

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requests: mark tests that need requests to function"
    )
    config.addinivalue_line(
        "markers", "json: mark tests that need json to function"
    )
    config.addinivalue_line(
        "markers", "xml: mark tests that need xml.etree to function"
    )


def pytest_collection_modifyitems(config, items):
    # Test for requests module
    skip_requests = pytest.mark.skip(reason="need requests module to run")
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        for item in items:
            if "requests" in item.keywords:
                item.add_marker(skip_requests)
    # Test for json module
    skip_json = pytest.mark.skip(reason="need json module to run")
    try:
        import json  # noqa: F401
    except ModuleNotFoundError:
        for item in items:
            if "json" in item.keywords:
                item.add_marker(skip_json)
    # Test for xml module
    skip_xml = pytest.mark.skip(reason="need xml module to run")
    try:
        import xml  # noqa: F401
    except ModuleNotFoundError:
        for item in items:
            if "xml" in item.keywords:
                item.add_marker(skip_xml)
    # Test if JSON statistics channel was enabled
    no_jsonstats = pytest.mark.skip(reason="need JSON statistics to be enabled")
    if os.getenv("HAVEJSONSTATS") is None:
        for item in items:
            if "json" in item.keywords:
                item.add_marker(no_jsonstats)
    # Test if XML statistics channel was enabled
    no_xmlstats = pytest.mark.skip(reason="need XML statistics to be enabled")
    if os.getenv("HAVEXMLSTATS") is None:
        for item in items:
            if "xml" in item.keywords:
                item.add_marker(no_xmlstats)


@pytest.fixture
def statsport(request):
    port = os.getenv("EXTRAPORT1")
    if port is None:
        port = 5301
    else:
        port = int(port)

    return port
