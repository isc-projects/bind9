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
import re
from typing import Optional

from .. import log


OPENSSL_VARS = {
    "OPENSSL_CONF": os.getenv("OPENSSL_CONF", None),
    "SOFTHSM2_CONF": os.getenv("SOFTHSM2_CONF", None),
    "SOFTHSM2_MODULE": None,
}


def parse_openssl_config(path: Optional[str]):
    if path is None or not os.path.exists(path):
        OPENSSL_VARS["SOFTHSM2_MODULE"] = None
        os.environ.pop("SOFTHSM2_MODULE", None)
        return
    assert os.path.isfile(path), f"{path} exists, but it's not a file"

    regex = re.compile(r"([^=]+)=(.*)")
    log.debug(f"parsing openssl config: {path}")
    with open(path, "r", encoding="utf-8") as conf:
        for line in conf:
            res = regex.match(line)
            if res:
                key = res.group(1).strip()
                val = res.group(2).strip()
                if key in ["MODULE_PATH", "pkcs11-module-path"]:
                    OPENSSL_VARS["SOFTHSM2_MODULE"] = val
                    os.environ["SOFTHSM2_MODULE"] = val
                    log.debug(
                        "SOFTHSM2_MODULE set to {OPENSSL_VARS['SOFTHSM2_MODULE']}"
                    )
