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

"""
Test that a second TKEY query with the same name is rejected with BADKEY.

RFC 3645 Section 4.1.1: if a non-expired key already exists for a
given name, the server must reject the query with BADKEY.

This test uses nsupdate -g with a fixed TKEY name (via the 'tkeyname'
command) to complete a real GSS-API TKEY negotiation, then runs
nsupdate -g again with the same TKEY name and verifies that the
server rejects it with BADKEY.
"""

import os
import subprocess

import pytest

import isctest
import isctest.mark

EXTRA_ARTIFACTS = pytest.mark.extra_artifacts(
    [
        "nsupdate.out*",
        "ns1/K*",
        "ns1/_default.tsigkeys",
        "ns1/example.nil.db",
        "ns1/example.nil.db.jnl",
    ]
)

pytestmark = [
    isctest.mark.with_gssapi,
    EXTRA_ARTIFACTS,
]

TKEY_NAME = "duptest.sig-example.nil."


def run_nsupdate_gss(ns1, tkey_name, record_name, record_value):
    """Run nsupdate -g with a fixed TKEY name.

    Returns the subprocess result.
    """
    nsupdate = isctest.vars.ALL["NSUPDATE"]
    port = ns1.ports.dns

    update_cmd = (
        f"gsstsig\n"
        f"tkeyname {tkey_name}\n"
        f"server {ns1.ip} {port}\n"
        f"zone example.nil.\n"
        f"update add {record_name} 86400 A {record_value}\n"
        f"send\n"
    )

    os.environ["KRB5CCNAME"] = f"FILE:{os.getcwd()}/ns1/administrator.ccache"

    return subprocess.run(
        [nsupdate, "-d"],
        input=update_cmd,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_tkey_duplicate_name_rejected(ns1):
    """Second TKEY query for an existing key name must return BADKEY.

    RFC 3645 Section 4.1.1: if a non-expired TSIG key exists for the
    name, the server must reject a new TKEY query for that name.
    """
    # Step 1: Complete a real GSS-API TKEY negotiation with a fixed name
    result = run_nsupdate_gss(ns1, TKEY_NAME, "duptest1.example.nil.", "10.53.0.99")
    assert (
        result.returncode == 0
    ), f"first nsupdate -g failed (rc={result.returncode}):\n{result.stderr}"

    # Step 2: Try the same TKEY name again — must fail
    result = run_nsupdate_gss(ns1, TKEY_NAME, "duptest2.example.nil.", "10.53.0.98")
    assert (
        result.returncode != 0
    ), "second nsupdate -g with duplicate TKEY name should have failed"
    assert (
        "BADKEY" in result.stderr or "REFUSED" in result.stderr
    ), f"expected BADKEY or REFUSED in error output, got:\n{result.stderr}"
