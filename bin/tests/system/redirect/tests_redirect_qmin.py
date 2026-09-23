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

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "dig.out.*",
        "ns1/K*",
        "ns1/*.signed",
        "ns1/dsset-nsec3.",
        "ns1/dsset-signed.",
        "ns1/nsec3.db",
        "ns1/signed.db",
        "ns2/example.db",
        "ns2/named.stats",
        "ns2/redirect.db",
        "ns3/K*",
        "ns3/*.signed",
        "ns3/dsset-nsec3.",
        "ns3/dsset-signed.",
        "ns3/nsec3.db",
        "ns3/signed.db",
        "ns4/example.db",
        "ns4/named.stats",
        "ns5/K*",
        "ns5/dsset-*",
        "ns5/*.signed",
        "ns5/root.db",
        "ns5/sign.ns5.*",
        "ns5/signed.db",
        "ns6/signed.db.signed",
        "ns9/K*",
        "ns9/dsset-*",
        "ns9/root.db",
        "ns9/root.db.signed",
        "ns9/sign.ns9.*",
        "ns10/trusted.conf",
        "ns11/trusted.conf",
    ]
)


def bootstrap():
    return {
        "redirect_zone": False,
    }


def test_nxdomain_redirect_qmin_mx_dnssec(ns11):
    ns11.rndc("flush")
    msg = isctest.query.create("nosuch.fake.test.", "MX", dnssec=True)

    # cold cache answer doesn't include proofs, so redirection is allowed
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.empty_answer(response)
    isctest.check.noerror(response)

    # hot cache answer does include proofs, so redirection is skipped
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.empty_answer(response)
    isctest.check.nxdomain(response)


def test_nxdomain_redirect_qmin_mx_no_dnssec(ns11):
    ns11.rndc("flush")
    msg = isctest.query.create("nosuch.spurious.test.", "MX", dnssec=False)
    for _ in range(2):
        response = isctest.query.tcp(msg, ns11.ip)
        isctest.check.noerror(response)
        isctest.check.empty_answer(response)


def test_nxdomain_redirect_qmin_a_dnssec(ns11):
    ns11.rndc("flush")
    msg = isctest.query.create("nosuch.fake.test.", "A", dnssec=True)

    # cold cache answer doesn't include proofs, so redirection is allowed
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.has_answer(response)
    isctest.check.noerror(response)

    # hot cache answer does include proofs, so redirection is skipped
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.empty_answer(response)
    isctest.check.nxdomain(response)


def test_nxdomain_redirect_qmin_any_dnssec(ns11):
    ns11.rndc("flush")
    msg = isctest.query.create("nosuch.fake.test.", "ANY", dnssec=True)

    # cold cache answer doesn't include proofs, so redirection is allowed
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.has_answer(response)
    isctest.check.noerror(response)

    # hot cache answer does include proofs, so redirection is skipped
    response = isctest.query.tcp(msg, ns11.ip)
    isctest.check.empty_answer(response)
    isctest.check.nxdomain(response)


def test_nxdomain_redirect_qmin_any_no_dnssec(ns11):
    ns11.rndc("flush")
    msg = isctest.query.create("nosuch.spurious.test.", "ANY", dnssec=False)
    for _ in range(2):
        response = isctest.query.tcp(msg, ns11.ip)
        isctest.check.noerror(response)
        isctest.check.has_answer(response)
