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

from pathlib import Path
from typing import Any

import os

import pytest

import isctest.mark
import isctest.template

EXTRA_ARTIFACTS = pytest.mark.extra_artifacts(
    [
        "openssl.cnf",
        "openssl_pin.cnf",
        "dig.out.*",
        "dsset-*",
        "keyfromlabel.err.*",
        "keyfromlabel.out.*",
        "pkcs11-tool.err.*",
        "pkcs11-tool.out.*",
        "signer.out.*",
        "ns*/dig.out.*",
        "ns*/K*",
        "ns*/keygen.out.*",
        "ns*/update.cmd.*",
        "ns*/update.log.*",
        "ns*/verify.out.*",
        "ns*/zone.*.jbk",
        "ns*/zone.*.jnl",
        "ns*/*.kskid1",
        "ns*/*.kskid2",
        "ns*/*.zskid1",
        "ns*/*.zskid2",
        "ns*/kryoptic.toml",
        "ns*/kryoptic.db",
        "ns1/keys",
        "ns1/*.example.db",
        "ns1/*.example.db.signed",
        "ns1/*.kasp.db",
        "ns1/*.kasp.db.signed",
        "ns1/*.split.db",
        "ns1/*.split.db.signed",
        "ns1/*.weird.db",
        "ns1/*.weird.db.signed",
        "ns2/keys",
        "ns2/*.view*.db",
        "ns2/*.view*.db.signed",
    ]
)

pytestmark = [
    isctest.mark.with_pkcs11_provider,
    isctest.mark.kryoptic_environment,
    EXTRA_ARTIFACTS,
]


def bootstrap() -> dict[str, Any]:
    templates = isctest.template.TemplateEngine(".")

    pin_path = Path.cwd().parent.joinpath("_common", "hsm_pin").resolve()

    database = Path.cwd().joinpath("ns1", "kryoptic.db").resolve()
    templates.render("ns1/kryoptic.toml", {"database": str(database)})

    database = Path.cwd().joinpath("ns2", "kryoptic.db").resolve()
    templates.render("ns2/kryoptic.toml", {"database": str(database)})

    templates.render(
        "openssl.cnf",
        {"pkcs11_module_path": os.environ["BIND9_TEST_KRYOPTIC_MODULE"]},
    )

    templates.render(
        "openssl_pin.cnf",
        {
            "pkcs11_module_path": os.environ["BIND9_TEST_KRYOPTIC_MODULE"],
            "pin_path": pin_path,
        },
    )

    return {"pin_path": pin_path}


def test_enginepkcs11(run_tests_sh):
    run_tests_sh()
