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

import os
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "requests: mark tests that need requests to function"
    )


def pytest_collection_modifyitems(config, items):
    # pylint: disable=unused-argument,unused-import,too-many-branches
    # pylint: disable=import-outside-toplevel
    # Test for requests module
    skip_requests = pytest.mark.skip(
        reason="need requests module to run")
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        for item in items:
            if "requests" in item.keywords:
                item.add_marker(skip_requests)


@pytest.fixture
def statsport(request):
    # pylint: disable=unused-argument
    env_port = os.getenv("EXTRAPORT1")
    if env_port is None:
        env_port = 5301
    else:
        env_port = int(env_port)

    return env_port
