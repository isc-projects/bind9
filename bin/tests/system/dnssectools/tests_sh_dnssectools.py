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
        "K*",
        "canonical*",
        "delv.out*",
        "dnssectools.out.*",
        "dsfromkey.out.*",
        "keygen*.err*",
        "*/K*",
        "*/dsset-*",
        "*/*.signed",
        "signer/example.db",
        "signer/example.db.after",
        "signer/example.db.before",
        "signer/example.db.changed",
        "signer/example2.db",
        "signer/example3.db",
        "signer/general/*.jnl",
        "signer/general/dnskey.expect",
        "signer/general/dsset-*",
        "signer/general/signed.expect",
        "signer/general/signed.zone",
        "signer/general/signer.out.*",
        "signer/nsec3param.out",
        "signer/prepub.db",
        "signer/revoke.example.db",
        "signer/signer.err.*",
        "signer/signer.out.*",
    ]
)


def test_dnssec(run_tests_sh):
    run_tests_sh()
