#!/usr/bin/python3

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
from pathlib import Path

import pytest

pytest.importorskip("dns", minversion="2.5.0")
import dns.name

import isctest

from typing import List


SUFFIX = dns.name.from_text("nsec3.example.")
ZONE = isctest.name.ZoneAnalyzer.read_path(
    Path(os.environ["builddir"]) / "selftest/analyzer.db", origin=SUFFIX
)


def text_to_names(texts: List[str]):
    return frozenset(dns.name.from_text(text, origin=SUFFIX) for text in texts)


def test_analyzer_delegations():
    assert ZONE.delegations == text_to_names(
        [
            "nsunder.dname",
            "nsunder.occluded.dname",
            "insecure",
            "secondns.insecure",
        ]
    )


def test_analyzer_dnames():
    assert ZONE.dnames == text_to_names(
        [
            "dname",
            "dname.insecure",
        ]
    )


def test_analyzer_ents():
    assert ZONE.ents == text_to_names(
        [
            "a.a",
            "a.a.a",
            "wild",
        ]
    )


def test_analyzer_occluded():
    assert ZONE.occluded == text_to_names(
        [
            "*.dname",
            "nsunder.dname",
            "*.nsunder.dname",
            "occluded.dname",
            "nsunder.occluded.dname",
            "occluded2.dname",
            "belowcut.insecure",
            "belowcut2.insecure",
            "dname.insecure",
            "ns.insecure",
            "secondns.insecure",
        ]
    )


def test_analyzer_reachable():
    assert ZONE.reachable == text_to_names(
        [
            "@",
            "02HC3EM7BDD011A0GMS3HKKJT2IF5VP8",
            "a",
            "a.a.a.a",
            "b",
            "d",
            "dname",
            "ns",
            "*.wild",
            "underwild.wild",
            "z",
        ]
    )


def test_analyzer_reachable_delegations():
    assert ZONE.reachable_delegations == text_to_names(
        [
            "insecure",
        ]
    )


def test_analyzer_reachable_dnames():
    assert ZONE.reachable_dnames == text_to_names(
        [
            "dname",
        ]
    )


def test_analyzer_reachable_wildcards():
    assert ZONE.reachable_wildcards == text_to_names(
        [
            "*.wild",
        ]
    )


def test_analyzer_wildcards():
    assert ZONE.wildcards == text_to_names(
        [
            "*.dname",
            "*.nsunder.dname",
            "*.wild",
        ]
    )
