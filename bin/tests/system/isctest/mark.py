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
import platform
import shutil
import socket
import subprocess

import pytest

long_test = pytest.mark.skipif(
    not os.environ.get("CI_ENABLE_LONG_TESTS"), reason="CI_ENABLE_LONG_TESTS not set"
)

live_internet_test = pytest.mark.skipif(
    not os.environ.get("CI_ENABLE_LIVE_INTERNET_TESTS"),
    reason="CI_ENABLE_LIVE_INTERNET_TESTS not set",
)


rsasha1 = pytest.mark.skipif(
    os.getenv("FEATURE_RSASHA1") != "1", reason="RSASHA1 disabled"
)


extended_ds_digest = pytest.mark.skipif(
    os.getenv("FEATURE_EXTENDED_DS_DIGEST") != "1",
    reason="extended DS digest algorithms disabled",
)


def _perl_module_available(module: str) -> bool:
    perl = os.environ.get("PERL", "perl")
    try:
        subprocess.run(
            [perl, f"-M{module}", "-e", ""],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


requires_net_dns = pytest.mark.skipif(
    not _perl_module_available("Net::DNS"),
    reason="Perl Net::DNS module is required",
)

requires_net_dns_nameserver = pytest.mark.skipif(
    not _perl_module_available("Net::DNS::Nameserver"),
    reason="Perl Net::DNS::Nameserver module is required",
)

requires_time_hires = pytest.mark.skipif(
    not _perl_module_available("Time::HiRes"),
    reason="Perl Time::HiRes module is required",
)


def is_host_freebsd(*_):
    return platform.system() == "FreeBSD"


def is_host_freebsd_13(*_):
    return platform.system() == "FreeBSD" and platform.release().startswith("13")


def with_algorithm(name: str):
    key = f"{name}_SUPPORTED"
    assert key in os.environ, f"{key} env variable undefined"
    return pytest.mark.skipif(os.getenv(key) != "1", reason=f"{name} is not supported")


with_eddsa = pytest.mark.skipif(
    os.getenv("ED25519_SUPPORTED") != "1" and os.getenv("ED448_SUPPORTED") != "1",
    reason="EdDSA (ED25519 or ED448) is not supported",
)


with_developer = pytest.mark.skipif(
    os.getenv("FEATURE_DEVELOPER") != "1",
    reason="developer mode disabled in the build",
)


with_dnstap = pytest.mark.skipif(
    os.getenv("FEATURE_DNSTAP") != "1", reason="DNSTAP support disabled in the build"
)


without_fips = pytest.mark.skipif(
    os.getenv("FEATURE_FIPS_MODE") == "1", reason="FIPS support enabled in the build"
)

with_libxml2 = pytest.mark.skipif(
    os.getenv("FEATURE_LIBXML2") != "1", reason="libxml2 support disabled in the build"
)


with_json_c = pytest.mark.skipif(
    os.getenv("FEATURE_JSON_C") != "1", reason="json-c support disabled in the build"
)

with_libnghttp2 = pytest.mark.skipif(
    os.getenv("FEATURE_LIBNGHTTP2") != "1",
    reason="libnghttp2 support disabled in the build",
)

with_geoip2 = pytest.mark.skipif(
    os.getenv("FEATURE_GEOIP2") != "1", reason="GeoIP2 support disabled in the build"
)

without_tsan = pytest.mark.skipif(
    os.getenv("FEATURE_TSAN") == "1", reason="incompatible with ThreadSanitizer (TSAN)"
)

with_cpu_affinity = pytest.mark.skipif(
    not (shutil.which("cpuset") or shutil.which("numactl") or shutil.which("taskset")),
    reason="cpuset, numactl, or taskset is required",
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


def have_ipv6():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind(("fd92:7065:b8e:ffff::1", 0))
    except OSError:
        return False
    return True


with_ipv6 = pytest.mark.skipif(not have_ipv6(), reason="IPv6 not available")

ecdsa_deterministic = False
try:
    from cryptography.hazmat.backends import default_backend

    ecdsa_deterministic = default_backend().ecdsa_deterministic_supported()
except Exception:  # pylint: disable=broad-except
    pass

with_ecdsa_deterministic = pytest.mark.skipif(
    not ecdsa_deterministic, reason="ECDSA deterministic signing is not supported"
)
