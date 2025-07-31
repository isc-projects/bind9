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
import shutil

import pytest

import isctest


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns4, templates):
    assert os.path.exists("ns4/managed-keys.bind.jnl") is False
    shutil.copyfile("ns4/managed-keys.bind.in", "ns4/managed-keys.bind")
    templates.render("ns4/named.conf", {"managed_key": True})
    ns4.reconfigure(log=False)


# helper functions
def getfrom(file):
    with open(file, encoding="utf-8") as f:
        return f.read().strip()


def test_secure_root_managed(ns4):
    # check that a query for a secure root validates
    msg = isctest.query.create(".", "KEY")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # check that "rndc secroots" dumps the trusted keys
    key = int(getfrom("ns1/managed.key.id"))
    alg = os.environ["DEFAULT_ALGORITHM"]
    expected = f"./{alg}/{key} ; managed"
    response = ns4.rndc("secroots -", log=False).splitlines()
    assert expected in response
    assert len(response) == 10


def test_positive_validation_nsec_managed():
    msg = isctest.query.create("a.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)


def test_positive_validation_nsec3_managed():
    msg = isctest.query.create("a.nsec3.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.noerror(res2)
    isctest.check.adflag(res2)


def test_positive_validation_optout_managed():
    msg = isctest.query.create("a.optout.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.3")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.adflag(res2)


def test_negative_validation_nsec_managed():
    # nxdomain
    msg = isctest.query.create("q.example", "A")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_answer(res1, res2)
    isctest.check.nxdomain(res2)
    isctest.check.adflag(res2)


def test_ds_managed():
    # check root DS queries validate
    msg = isctest.query.create(".", "DS")
    res1 = isctest.query.tcp(msg, "10.53.0.1")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.adflag(res2)
    isctest.check.noerror(res2)

    # check DS queries succeed at RFC 1918 empty zone
    msg = isctest.query.create("10.in-addr.arpa", "DS")
    res1 = isctest.query.tcp(msg, "10.53.0.2")
    res2 = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.same_data(res1, res2)
    isctest.check.noerror(res2)


def test_keydata_storage(ns4):
    ns4.rndc("managed-keys sync", log=False)
    with isctest.log.WatchLogFromStart("ns4/managed-keys.bind") as watcher:
        watcher.wait_for_line(["KEYDATA", "next refresh:"])
