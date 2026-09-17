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
import subprocess

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.bk",
        "*/*.conf",
        "*/*.db",
        "*/*.id",
        "*/*.jnl",
        "*/*.jbk",
        "*/*.key",
        "*/*.signed",
        "*/settime.out.*",
        "ans*/ans.run",
        "*/trusted.keys",
        "*/*.bad",
        "*/*.next",
        "*/*.stripped",
        "*/*.tmp",
        "*/*.stage?",
        "*/*.patched",
        "*/*.lower",
        "*/*.upper",
        "*/*.unsplit",
    ]
)


# run delv
def delv(*args, tkeys=False):
    delv_cmd = [os.environ.get("DELV")]

    tfile = "ns1/trusted.keys" if tkeys else "ns1/trusted.conf"
    delv_cmd.extend(["@10.53.0.4", "-a", tfile, "-p", os.environ["PORT"]])
    delv_cmd.extend(args)

    return isctest.run.cmd(delv_cmd, stderr=subprocess.STDOUT)


def test_positive_validation_delv():
    # check positive validation NSEC
    response = delv("a", "a.example")
    assert Re("a.example..*10.0.0.1") in response.out
    assert Re("a.example..*.RRSIG.A [0-9][0-9]* 2 300 .*") in response.out

    # check positive validation NSEC (trsuted-keys)
    response = delv("a", "a.example", tkeys=True)
    assert Re("a.example..*10.0.0.1") in response.out
    assert Re("a.example..*.RRSIG.A [0-9][0-9]* 2 300 .*") in response.out

    # check positive validation NSEC3
    response = delv("a", "a.nsec3.example")
    assert Re("a.nsec3.example..*10.0.0.1") in response.out
    assert Re("a.nsec3.example..*.RRSIG.A [0-9][0-9]* 3 300 .*") in response.out

    # check positive validation OPTOUT
    response = delv("a", "a.optout.example")
    assert Re("a.optout.example..*10.0.0.1") in response.out
    assert Re("a.optout.example..*.RRSIG.A [0-9][0-9]* 3 300 .*") in response.out

    # check positive wildcard validation NSEC
    response = delv("a", "a.wild.example")
    assert Re("a.wild.example..*10.0.0.27") in response.out
    assert Re("a.wild.example..*.RRSIG.A [0-9][0-9]* 2 300 .*") in response.out

    # check positive wildcard validation NSEC3
    response = delv("a", "a.wild.nsec3.example")
    assert Re("a.wild.nsec3.example..*10.0.0.6") in response.out
    assert Re("a.wild.nsec3.example..*.RRSIG.A [0-9][0-9]* 3 300 .*") in response.out

    # check positive wildcard validation OPTOUT
    response = delv("a", "a.wild.optout.example")
    assert Re("a.wild.optout.example..*10.0.0.6") in response.out
    assert Re("a.wild.optout.example..*.RRSIG.A [0-9][0-9]* 3 300 .*") in response.out


def test_negative_validation_delv():
    # checking negative validation NXDOMAIN NSEC
    response = delv("a", "q.example")
    assert "resolution failed: ncache nxdomain" in response.out

    # checking negative validation NODATA NSEC
    response = delv("txt", "a.example")
    assert "resolution failed: ncache nxrrset" in response.out

    # checking negative validation NXDOMAIN NSEC3
    response = delv("a", "q.nsec3.example")
    assert "resolution failed: ncache nxdomain" in response.out

    # checking negative validation NODATA NSEC3
    response = delv("txt", "a.nsec3.example")
    assert "resolution failed: ncache nxrrset" in response.out

    # checking negative validation NXDOMAIN OPTOUT
    response = delv("a", "q.optout.example")
    assert "resolution failed: ncache nxdomain" in response.out

    # checking negative validation NODATA OPTOUT
    response = delv("txt", "a.optout.example")
    assert "resolution failed: ncache nxrrset" in response.out

    # checking negative wildcard validation NSEC
    response = delv("txt", "b.wild.example")
    assert "resolution failed: ncache nxrrset" in response.out

    # checking negative wildcard validation NSEC3
    response = delv("txt", "b.wild.nsec3.example")
    assert "resolution failed: ncache nxrrset" in response.out

    # checking negative wildcard validation OPTOUT
    response = delv("txt", "b.wild.optout.example")
    assert "resolution failed: ncache nxrrset" in response.out


def test_insecure_validation_delv():
    # check 1-server insecurity proof NSEC
    response = delv("a", "a.insecure.example")
    assert Re("a.insecure.example..*10.0.0.1") in response.out

    # check 1-server insecurity proof NSEC3
    response = delv("a", "a.insecure.nsec3.example")
    assert Re("a.insecure.nsec3.example..*10.0.0.1") in response.out

    # check 1-server insecurity proof NSEC3
    response = delv("a", "a.insecure.optout.example")
    assert Re("a.insecure.optout.example..*10.0.0.1") in response.out

    # check 1-server negative insecurity proof NSEC
    response = delv("a", "q.insecure.example")
    assert "resolution failed: ncache nxdomain" in response.out

    # check 1-server negative insecurity proof NSEC3
    response = delv("a", "q.insecure.nsec3.example")
    assert "resolution failed: ncache nxdomain" in response.out

    # check 1-server negative insecurity proof OPTOUT
    response = delv("a", "q.insecure.optout.example")
    assert "resolution failed: ncache nxdomain" in response.out


def test_validation_failure_delv():
    # check failed validation due to bogus data
    response = delv("+cd", "a", "a.bogus.example")
    assert "resolution failed: RRSIG failed to verify" in response.out

    # check failed validation due to missing key record
    response = delv("+cd", "a", "a.b.keyless.example")
    assert "resolution failed: insecurity proof failed" in response.out


def test_revoked_key_delv():
    # check failed validation succeeds when a revoked key is encountered
    response = delv("+cd", "soa", "revkey.example")
    assert "fully validated" in response.out
