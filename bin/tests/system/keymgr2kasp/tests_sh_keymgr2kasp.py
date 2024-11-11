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
        "ns*/K*",
        "ns*/kasp.conf",
        "ns*/keygen.out*",
        "ns*/signer.out*",
        "ns*/zones",
        "ns*/dsset-*",
        "ns*/*.db",
        "ns*/*.db.jnl",
        "ns*/*.db.jbk",
        "ns*/*.db.signed*",
        "ns*/*.db.infile",
        "ns*/managed-keys.bind*",
        "ns*/*.mkeys*",
        "*.created",
        "created.key-*",
        "dig.out*",
        "python.out.*",
        "retired.*",
        "rndc.dnssec.*",
        "unused.key*",
        "verify.out.*",
    ]
)


def test_keymgr2kasp(run_tests_sh):
    run_tests_sh()
