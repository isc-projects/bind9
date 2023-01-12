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


# ======================= LEGACY=COMPATIBLE FIXTURES =========================
# The following fixtures are designed to work with both pytest system test
# runner and the legacy system test framework.


@pytest.fixture(scope="module")
def named_port():
    return int(os.environ.get("PORT", default=5300))


@pytest.fixture(scope="module")
def named_tlsport():
    return int(os.environ.get("TLSPORT", default=8853))


@pytest.fixture(scope="module")
def named_httpsport():
    return int(os.environ.get("HTTPSPORT", default=4443))


@pytest.fixture(scope="module")
def control_port():
    return int(os.environ.get("CONTROLPORT", default=9953))


# ======================= PYTEST SYSTEM TEST RUNNER ==========================
# From this point onward, any setting, fixtures or functions only apply to the
# new pytest runner. Ideally, these would be in a separate file. However, due
# to how pytest works and how it's used by the legacy runner, the best approach
# is to have everything in this file to avoid duplication and set the
# LEGACY_TEST_RUNNER if pytest is executed from the legacy framework.
#
# FUTURE: Once legacy runner is no longer supported, remove the env var and
# don't branch the code.

if os.getenv("LEGACY_TEST_RUNNER", "0") == "0":
    pass  # will be implemented in followup commits
