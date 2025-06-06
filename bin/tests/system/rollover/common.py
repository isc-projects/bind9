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

from datetime import timedelta
import os

import pytest

pytestmark = pytest.mark.extra_artifacts(
    [
        "*.axfr*",
        "dig.out*",
        "K*.key*",
        "K*.private*",
        "ns*/*.db",
        "ns*/*.db.infile",
        "ns*/*.db.jnl",
        "ns*/*.db.jbk",
        "ns*/*.db.signed",
        "ns*/*.db.signed.jnl",
        "ns*/*.conf",
        "ns*/dsset-*",
        "ns*/K*.key",
        "ns*/K*.private",
        "ns*/K*.state",
        "ns*/keygen.out.*",
        "ns*/settime.out.*",
        "ns*/signer.out.*",
        "ns*/zones",
    ]
)


TIMEDELTA = {
    0: timedelta(seconds=0),
    "PT5M": timedelta(minutes=5),
    "PT1H": timedelta(hours=1),
    "PT2H": timedelta(hours=2),
    "P1D": timedelta(days=1),
    "P5D": timedelta(days=5),
    "P10D": timedelta(days=10),
    "P14D": timedelta(days=14),
    "P60D": timedelta(days=60),
    "P90D": timedelta(days=90),
    "P6M": timedelta(days=31 * 6),
    "P1Y": timedelta(days=365),
}
DURATION = {isoname: int(delta.total_seconds()) for isoname, delta in TIMEDELTA.items()}
CDSS = ["CDNSKEY", "CDS (SHA-256)"]
DEFAULT_CONFIG = {
    "dnskey-ttl": TIMEDELTA["PT1H"],
    "ds-ttl": TIMEDELTA["P1D"],
    "max-zone-ttl": TIMEDELTA["P1D"],
    "parent-propagation-delay": TIMEDELTA["PT1H"],
    "publish-safety": TIMEDELTA["PT1H"],
    "purge-keys": TIMEDELTA["P90D"],
    "retire-safety": TIMEDELTA["PT1H"],
    "signatures-refresh": TIMEDELTA["P5D"],
    "signatures-validity": TIMEDELTA["P14D"],
    "zone-propagation-delay": TIMEDELTA["PT5M"],
}
UNSIGNING_CONFIG = DEFAULT_CONFIG.copy()
UNSIGNING_CONFIG["dnskey-ttl"] = TIMEDELTA["PT2H"]


@pytest.fixture
def alg():
    return os.environ["DEFAULT_ALGORITHM_NUMBER"]


@pytest.fixture
def size():
    return os.environ["DEFAULT_BITS"]
