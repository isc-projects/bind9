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

import hashlib
import os
import shutil

import pytest

from isctest.util import param

import isctest.mark

pytestmark = [
    isctest.mark.kryoptic_environment,
    pytest.mark.extra_artifacts(
        [
            "*.example.db",
            "*.example.db.signed",
            "K*",
            "dsset-*",
            "keyfromlabel.out.*",
            "pkcs11-tool.out.*",
            "signer.out.*",
            "kryoptic.db",
            "kryoptic.toml",
            "openssl.cnf",
        ],
    ),
]

HSMPIN = None
SOPIN = None


def bootstrap() -> dict[str, Any]:
    global HSMPIN  # pylint: disable=global-statement
    HSMPIN = (
        Path.cwd().parent.joinpath("_common", "hsm_pin").read_text(encoding="utf-8")
    )

    global SOPIN  # pylint: disable=global-statement
    SOPIN = Path.cwd().parent.joinpath("_common", "so_pin").read_text(encoding="utf-8")

    templates = isctest.template.TemplateEngine(".")

    database = Path.cwd() / "kryoptic.db"
    templates.render("kryoptic.toml", {"database": str(database)})

    templates.render(
        "openssl.cnf",
        {
            "pkcs11_module_path": os.environ["BIND9_TEST_KRYOPTIC_MODULE"],
            "pin_path": Path.cwd().parent.joinpath("_common", "hsm_pin").resolve(),
        },
    )

    return {}


@pytest.fixture(autouse=True)
def token_init_and_cleanup():
    token_env = {
        **os.environ,
        "OPENSSL_CONF": "",
        "KRYOPTIC_CONF": Path.cwd().joinpath("kryoptic.toml").as_posix(),
    }

    token_init_command = [
        "pkcs11-tool",
        "--module",
        os.environ["BIND9_TEST_KRYOPTIC_MODULE"],
        "--init-token",
        "--label",
        "kryoptic-keyfromlabel",
        "--so-pin",
        SOPIN,
    ]

    token_pin_init_command = [
        "pkcs11-tool",
        "--module",
        os.environ["BIND9_TEST_KRYOPTIC_MODULE"],
        "--init-pin",
        "--login",
        "--login-type",
        "so",
        "--so-pin",
        SOPIN,
        "--pin",
        HSMPIN,
    ]

    database = Path.cwd() / "kryoptic.db"

    try:
        cmd = isctest.run.cmd(token_init_command, env=token_env)
        assert "Token successfully initialized" in cmd.out
        cmd = isctest.run.cmd(token_pin_init_command, env=token_env)
        assert "User PIN successfully initialized" in cmd.out
        assert database.exists()
        yield
    finally:
        database.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "alg_name,alg_type,alg_bits",
    [
        ("rsasha256", "rsa", "2048"),
        ("rsasha512", "rsa", "2048"),
        ("ecdsap256sha256", "EC", "prime256v1"),
        ("ecdsap384sha384", "EC", "prime384v1"),
        param(
            "ed25519",
            "EC",
            "Ed25519",
            marks=pytest.mark.skipif(
                os.environ.get("ED25519_SUPPORTED") != "1",
                reason="Ed25519 not supported by this build",
            ),
        ),
        param(
            "ed448",
            "EC",
            "Ed448",
            marks=pytest.mark.skipif(
                os.environ.get("ED448_SUPPORTED") != "1",
                reason="Ed448 not supported by this build",
            ),
        ),
    ],
)
def test_keyfromlabel(alg_name, alg_type, alg_bits):
    test_env = {
        **os.environ,
        "OPENSSL_CONF": Path.cwd().joinpath("openssl.cnf").as_posix(),
        "KRYOPTIC_CONF": Path.cwd().joinpath("kryoptic.toml").as_posix(),
    }

    def keygen(alg_type, alg_bits, label):
        p11_id = hashlib.sha1(label.encode("utf-8")).hexdigest()

        pkcs11_command = [
            "pkcs11-tool",
            "--module",
            os.environ.get("BIND9_TEST_KRYOPTIC_MODULE"),
            "--token-label",
            "kryoptic-keyfromlabel",
            "-l",
            "-k",
            "--key-type",
            f"{alg_type}:{alg_bits}",
            "--label",
            label,
            "--id",
            p11_id,
            "--pin",
            HSMPIN,
        ]

        cmd = isctest.run.cmd(pkcs11_command, env=test_env)

        assert "Key pair generated" in cmd.out

    def keyfromlabel(alg_name, zone, label, key_flag):
        key_flag = key_flag.split() if key_flag else []

        keyfrlab_command = [
            os.environ["KEYFRLAB"],
            "-a",
            alg_name,
            "-y",
            "-l",
            f"pkcs11:token=kryoptic-keyfromlabel;object={label};pin-source=../_common/hsm_pin",
            *key_flag,
            zone,
        ]

        cmd = isctest.run.cmd(keyfrlab_command, env=test_env, raise_on_exception=False)
        if cmd.rc != 0 and "already exists" in cmd.err:
            return None
        assert cmd.rc == 0
        keyfile = cmd.out.rstrip() + ".key"

        assert os.path.exists(keyfile)

        return keyfile

    def hsm_key(alg_type, alg_bits, alg_name, zone, key_id, key_flag):
        # Unlike dnssec-keygen, pkcs11-tool does not avoid key tag collisions,
        # so dnssec-keyfromlabel may refuse a key. Replace it then.
        keyfile = None
        for attempt in range(3):
            label = f"{key_id}-{attempt}-{zone}"
            keygen(alg_type, alg_bits, label)
            keyfile = keyfromlabel(alg_name, zone, label, key_flag)
            if keyfile is not None:
                break
        assert keyfile is not None, f"{key_id}: key tags keep colliding"
        return keyfile

    if f"{alg_name.upper()}_SUPPORTED" not in os.environ:
        pytest.skip(f"{alg_name} is not supported")

    # Generate keys for the $zone zone
    zone = f"{alg_name}.example"

    # Get ZSK
    zsk_file = hsm_key(alg_type, alg_bits, alg_name, zone, "keyfromlabel-zsk", "")

    # Get KSK
    ksk_file = hsm_key(alg_type, alg_bits, alg_name, zone, "keyfromlabel-ksk", "-f KSK")

    # Sign zone with KSK and ZSK
    zone_file = f"zone.{alg_name}.example.db"

    with open(zone_file, "w", encoding="utf-8") as outfile:
        for f in ["template.db.in", ksk_file, zsk_file]:
            with open(f, "r", encoding="utf-8") as fd:
                shutil.copyfileobj(fd, outfile)

    signer_command = [
        os.environ["SIGNER"],
        "-S",
        "-a",
        "-g",
        "-o",
        zone,
        zone_file,
    ]
    isctest.run.cmd(signer_command, env=test_env)

    assert os.path.exists(f"{zone_file}.signed")
