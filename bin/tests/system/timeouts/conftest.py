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
        "markers", "long: mark tests that take a long time to run"
    )


def pytest_collection_modifyitems(config, items):
    # pylint: disable=unused-argument,unused-import,too-many-branches
    # pylint: disable=import-outside-toplevel
    skip_long_tests = pytest.mark.skip(
        reason="need CI_ENABLE_ALL_TESTS environment variable")
    if not os.environ.get("CI_ENABLE_ALL_TESTS"):
        for item in items:
            if "long" in item.keywords:
                item.add_marker(skip_long_tests)
