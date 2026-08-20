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

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "K*",
        "canonical*",
        "delv.out*",
        "dnssectools.out.*",
        "dsfromkey.out.*",
        "kasp.conf",
        "keygen*.err*",
        "*/K*",
        "*/dsset-*",
        "*/*.signed",
        "dsset-*",
        "conf/*.conf",
        "signer.err.*",
        "signer.out.*",
        "verify.err.*",
        "verify.out.*",
        "signer/bad.db",
        "signer/example.com",
        "signer/dnssec-records.*",
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
        "signer/maxcbm.example.db",
        "signer/nsec3param.out",
        "signer/prepub.db",
        "signer/revoke.example.db",
        "signer/signer.err.*",
        "signer/signer.out.*",
    ]
)


# run named-checkconf
def checkconf(cfgfile):
    checkconf_cmd = [os.environ.get("CHECKCONF"), "-k", cfgfile]
    return isctest.run.cmd(checkconf_cmd, raise_on_exception=False)


# run dnssec-keygen
def keygen(*args):
    keygen_cmd = [os.environ.get("KEYGEN")]
    keygen_cmd.extend(args)
    return isctest.run.cmd(keygen_cmd, raise_on_exception=False)


def test_keygen_keystore_keydirectory():
    zone = "keystore-keydirectory.example."
    conf = "conf/keystore-keydirectory.conf"
    policy = "csk"

    # named-checkconf should complain about the key-store name.
    result = checkconf(conf)
    assert "name 'key-directory' not allowed" in result.out

    # dnssec-keygen should also complain about the key-store name.
    result = keygen("-k", policy, "-l", conf, zone)
    assert "key-store: duplicate key-store found 'key-directory'" in result.err
