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

from re import compile as Re

import os

from .. import log

OPENSSL_VARS = {
    "OPENSSL_CONF": os.getenv("OPENSSL_CONF", None),
    "BIND9_TEST_KRYOPTIC_MODULE": os.getenv("BIND9_TEST_KRYOPTIC_MODULE", None),
}


def parse_openssl_config(path: str | None):
    # An explicitly set module takes precedence over the OpenSSL config.
    if OPENSSL_VARS["BIND9_TEST_KRYOPTIC_MODULE"] is not None:
        return
    if path is None or not os.path.exists(path):
        return
    assert os.path.isfile(path), f"{path} exists, but it's not a file"

    regex = Re(r"([^=]+)=(.*)")
    log.debug(f"parsing openssl config: {path}")
    with open(path, "r", encoding="utf-8") as conf:
        for line in conf:
            res = regex.match(line)
            if res:
                key = res.group(1).strip()
                val = res.group(2).strip()
                if key in ["MODULE_PATH", "pkcs11-module-path"]:
                    OPENSSL_VARS["BIND9_TEST_KRYOPTIC_MODULE"] = val
                    os.environ["BIND9_TEST_KRYOPTIC_MODULE"] = val
                    log.debug(
                        f"BIND9_TEST_KRYOPTIC_MODULE set to {OPENSSL_VARS['BIND9_TEST_KRYOPTIC_MODULE']}"
                    )
