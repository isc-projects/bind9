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
Check the dnstap file output: the frames logged for authoritative, recursive
and forwarding traffic, the reopen/roll commands, and the dnstap-read formats.
"""

from re import compile as Re

import os
import re

import dns.update
import pytest
import yaml

from dnstap.common import ARTIFACTS, check_counts, dnstap_read
from isctest.util import param

import isctest
import isctest.mark

pytestmark = [
    isctest.mark.with_dnstap,
    pytest.mark.requires_zones_loaded("ns1", "ns2", "ns3", "ns4", "ns5"),
    pytest.mark.extra_artifacts(ARTIFACTS),
]


def query(server, qname="a.example.", qtype="A"):
    msg = isctest.query.create(qname, qtype)
    return isctest.query.udp(msg, server.ip)


@pytest.fixture(scope="module", autouse=True)
def captures(ns1, ns2, ns3, ns5):
    """
    Generate the dnstap traffic and flush it to disk.

    After this fixture runs, "nsX/dnstap.out.save" holds the frames logged
    before the output files were reopened and "nsX/dnstap.out" the frames
    logged afterwards.
    """
    # Both the 'a.example/A' lookup and the './NS' lookup to ns1 need to
    # complete before reopening/rolling for the counts to be correct.
    with ns1.watch_log_from_start() as watcher:
        query(ns3)
        watcher.wait_for_line("(.): reset client")

    # Check three different dnstap reopen/roll methods:
    for ns in (ns1, ns2, ns5):
        os.rename(f"{ns}/dnstap.out", f"{ns}/dnstap.out.save")
    ns1.rndc("dnstap-reopen")
    ns2.rndc("dnstap -reopen")
    ns3.rndc("dnstap -roll")
    ns5.rndc("dnstap -reopen")

    # Send test traffic.
    query(ns5)
    update = dns.update.Update("example")
    update.add("b.example.", 3600, "A", "10.10.10.10")
    ns2.nsupdate(update)

    # File output should be flushed once a second according to the libfstrm
    # source, but it doesn't seem to happen until enough data has
    # accumulated. To get all the output, we stop the name servers, forcing
    # a flush on shutdown. It would be nice to find a better way to do this.
    for ns in (ns1, ns2, ns3, ns5):
        ns.stop()

    os.rename("ns3/dnstap.out.0", "ns3/dnstap.out.save")


@pytest.mark.parametrize(
    "ns, expected",
    [
        param("ns1", {"TCP": 6, "AQ": 3, "AR": 2, "CR": 1}),
        param("ns2", {"UDP": 2, "TCP": 2, "AQ": 2, "AR": 1, "CR": 1}),
        param("ns3", {"UDP": 4, "TCP": 6, "AQ": 1, "CQ": 1, "CR": 2, "RQ": 3, "RR": 3}),
        param("ns5", {"TCP": 2, "AQ": 1, "CR": 1}),
    ],
)
def test_initial_counts(ns, expected):
    check_counts(f"{ns}/dnstap.out.save", expected)


@pytest.mark.parametrize(
    "ns, expected",
    [
        param("ns1", {}),
        param("ns2", {"UDP": 2, "UQ": 1, "UR": 1}),
        param("ns3", {"UDP": 2, "CQ": 1, "CR": 1}),
        param("ns5", {"UDP": 4, "CQ": 1, "CR": 1, "FQ": 1, "FR": 1}),
    ],
)
def test_reopened_counts(ns, expected):
    check_counts(f"{ns}/dnstap.out", expected)


def test_client_query_destination_port(ns3, named_port):
    """
    Check that the destination UDP port is logged for client queries.
    """
    pattern = Re(rf"CQ [0-9:.]+ -> {re.escape(ns3.ip)}:{named_port} UDP")
    assert pattern in dnstap_read("ns3/dnstap.out.save").out


def test_yaml_output():
    frames = list(yaml.safe_load_all(dnstap_read("ns3/dnstap.out.save", "-y").out))
    assert frames
    for frame in frames:
        assert frame["type"] == "MESSAGE"
        assert frame["identity"] == "ns3"
        assert frame["version"] == "xxx"


def test_hex_output():
    hexdump = dnstap_read("ns3/dnstap.out", "-x").out.splitlines()[-1]
    result = isctest.run.cmd(
        [os.environ["WIRETEST"]], input_text=hexdump.encode("ascii")
    )
    assert "status: NOERROR" in result.out
    assert "ANSWER: 3, AUTHORITY: 0" in result.out
