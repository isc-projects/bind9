# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os
import subprocess

# The flags below are the subset of newer branches' feature probes that this
# branch's feature-test binary understands.  Probes absent here (developer,
# fips-dh, fips-mode, fips-provider, openssl-cipher-suites, rsasha1) leave
# their FEATURE_* variable unset, so the corresponding isctest.mark markers
# degrade to unconditional skips.
FEATURES = {
    "DNSRPS": "--enable-dnsrps",
    "DNSTAP": "--enable-dnstap",
    "GEOIP2": "--have-geoip2",
    "GSSAPI": "--gssapi",
    "JSON_C": "--have-json-c",
    "LIBIDN2": "--with-libidn2",
    "LIBNGHTTP2": "--with-libnghttp2",
    "LIBXML2": "--have-libxml2",
    "LMDB": "--with-lmdb",
    "MD5": "--md5",
    "QUERYTRACE": "--enable-querytrace",
    "TSAN": "--tsan",
    "ZLIB": "--with-zlib",
}

FEATURE_VARS: dict[str, str] = {}


def feature_test(feature):
    feature_test_bin = os.environ.get("FEATURETEST", "")
    if not feature_test_bin:  # this can be the case when running doctest
        return False
    try:
        subprocess.run([feature_test_bin, feature], check=True)
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        return False
    return True


def init_features():
    """
    Initialize the environment variables indicating feature support.
    """
    for name, arg in FEATURES.items():
        supported = feature_test(arg)
        envvar = f"FEATURE_{name}"
        val = "1" if supported else "0"
        FEATURE_VARS[envvar] = val
        os.environ[envvar] = val
