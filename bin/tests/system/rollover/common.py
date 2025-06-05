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
