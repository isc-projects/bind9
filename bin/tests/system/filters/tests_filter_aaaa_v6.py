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

import isctest.mark

from filters.common import (
    ARTIFACTS,
    check_filter,
    check_filter_other_family,
    prime_cache,
    reconfigure_servers,
)


pytestmark = pytest.mark.extra_artifacts(ARTIFACTS)


@pytest.fixture(scope="module", autouse=True)
def setup_filters(servers, templates):
    isctest.log.info("configuring server to filter AAAA on V6")
    reconfigure_servers("aaaa", "v6", servers, templates)
    prime_cache("fd92:7065:b8e:ffff::2")
    prime_cache("fd92:7065:b8e:ffff::3")


@isctest.mark.with_ipv6
@pytest.mark.parametrize(
    "addr, altaddr, break_dnssec, recursive",
    [
        pytest.param(
            "fd92:7065:b8e:ffff::1", "fd92:7065:b8e:ffff::2", False, False, id="auth"
        ),
        pytest.param(
            "fd92:7065:b8e:ffff::4",
            "fd92:7065:b8e:ffff::2",
            True,
            False,
            id="auth-break-dnssec",
        ),
        pytest.param(
            "fd92:7065:b8e:ffff::2",
            "fd92:7065:b8e:ffff::1",
            False,
            True,
            id="recurs",
        ),
        pytest.param(
            "fd92:7065:b8e:ffff::3",
            "fd92:7065:b8e:ffff::1",
            True,
            True,
            id="recurs-break-dnssec",
        ),
    ],
)
def test_filter_aaaa_on_v6(addr, altaddr, break_dnssec, recursive):
    check_filter(addr, altaddr, "aaaa", break_dnssec, recursive)


@isctest.mark.with_ipv6
@pytest.mark.parametrize(
    "addr",
    [
        pytest.param("10.53.0.1", id="auth"),
        pytest.param("10.53.0.4", id="auth-break-dnssec"),
        pytest.param("10.53.0.2", id="recurs"),
        pytest.param("10.53.0.3", id="recurs-break-dnssec"),
    ],
)
def test_filter_aaaa_on_v6_via_v4(addr):
    check_filter_other_family(addr, "aaaa")
