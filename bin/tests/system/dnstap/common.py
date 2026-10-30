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

"""
Helpers shared by the dnstap system test modules.
"""

from collections import Counter

import os

import isctest

ARTIFACTS = [
    "dnstap.out*",
    "fstrm_capture.out.*",
    "ns*/dnstap.out*",
    "ns2/example.db",
    "ns2/example.db.jnl",
]


def dnstap_read(path: str, *opts: str) -> isctest.run.CmdResult:
    """
    Run dnstap-read on a capture file with optional extra options.
    """
    return isctest.run.cmd([os.environ["DNSTAPREAD"], *opts, path])


def message_counts(path: str) -> Counter:
    """
    Count dnstap frames in a capture file by message type (AQ, CR, ...) and
    by transport protocol (UDP, TCP).

    Each line of dnstap-read output looks like:

        22-Jun-2022 12:09:06.168 RQ 10.53.0.3:56306 -> 10.53.0.2:7523 UDP 54b example/IN/A
    """
    counts: Counter = Counter()
    for line in dnstap_read(path).out.splitlines():
        fields = line.split()
        counts[fields[2]] += 1
        for protocol in ("UDP", "TCP"):
            if protocol in fields:
                counts[protocol] += 1
    return counts


def check_counts(path: str, expected: dict[str, int]) -> None:
    """
    Assert the frame counts in a capture file match the expectation exactly.
    Message types and protocols with no expected frames may be omitted from
    `expected`.
    """
    assert message_counts(path) == Counter(expected)
