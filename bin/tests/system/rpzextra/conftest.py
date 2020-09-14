############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

import os
import pytest

try:
    import dns.resolver  # noqa: F401 # pylint: disable=unused-import
except ModuleNotFoundError:
    dns_resolver_module_found = False
else:
    dns_resolver_module_found = True


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "dnspython: mark tests that need dnspython to function"
    )


def pytest_collection_modifyitems(config, items):
    # pylint: disable=unused-argument
    # Test for dnspython module
    if not dns_resolver_module_found:
        skip_requests = pytest.mark.skip(reason="need dnspython module to run")
        for item in items:
            if "dnspython" in item.keywords:
                item.add_marker(skip_requests)
    # Test if JSON statistics channel was enabled
    no_jsonstats = pytest.mark.skip(reason="need JSON statistics to be enabled")
    if os.getenv("HAVEJSONSTATS") is None:
        for item in items:
            if "json" in item.keywords:
                item.add_marker(no_jsonstats)


@pytest.fixture
def named_port(request):
    # pylint: disable=unused-argument
    port = os.getenv("PORT")
    if port is None:
        port = 5301
    else:
        port = int(port)

    return port
