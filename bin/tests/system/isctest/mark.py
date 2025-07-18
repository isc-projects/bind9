#!/usr/bin/python3

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
from pathlib import Path
import platform
import shutil
import ssl
import subprocess

import pytest


long_test = pytest.mark.skipif(
    not os.environ.get("CI_ENABLE_LONG_TESTS"), reason="CI_ENABLE_LONG_TESTS not set"
)

live_internet_test = pytest.mark.skipif(
    not os.environ.get("CI_ENABLE_LIVE_INTERNET_TESTS"),
    reason="CI_ENABLE_LIVE_INTERNET_TESTS not set",
)


def feature_test(feature):
    feature_test_bin = os.environ.get("FEATURETEST")
    if not feature_test_bin:  # this can be the case when running doctest
        return False
    try:
        subprocess.run([feature_test_bin, feature], check=True)
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        return False
    return True


DNSRPS_BIN = Path(os.environ["TOP_BUILDDIR"]) / "bin/tests/system/rpz/dnsrps"


def is_dnsrps_available():
    if not feature_test("--enable-dnsrps"):
        return False
    try:
        subprocess.run([DNSRPS_BIN, "-a"], check=True)
    except subprocess.CalledProcessError:
        return False
    return True


def is_host_freebsd_13(*_):
    return platform.system() == "FreeBSD" and platform.release().startswith("13")


have_libxml2 = pytest.mark.skipif(
    not feature_test("--have-libxml2"), reason="libxml2 support disabled in the build"
)

have_json_c = pytest.mark.skipif(
    not feature_test("--have-json-c"), reason="json-c support disabled in the build"
)

dnsrps_enabled = pytest.mark.skipif(
    not is_dnsrps_available(), reason="dnsrps disabled in the build"
)

supported_openssl_version = pytest.mark.skipif(
    ssl.OPENSSL_VERSION_NUMBER >= 0x300000C0
    and ssl.OPENSSL_VERSION_NUMBER < 0x300000E0,
    reason="unsupported OpenSSL [GL #4814]",
)


softhsm2_environment = pytest.mark.skipif(
    not (
        os.getenv("SOFTHSM2_CONF")
        and os.getenv("SOFTHSM2_MODULE")
        and shutil.which("pkcs11-tool")
        and shutil.which("softhsm2-util")
    ),
    reason="SOFTHSM2_CONF and SOFTHSM2_MODULE environmental variables must be set and pkcs11-tool and softhsm2-util tools present",
)
