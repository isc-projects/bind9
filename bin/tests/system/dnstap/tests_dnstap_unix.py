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
Check the "rndc dnstap" commands: -reopen against a unix socket output read
by fstrm_capture.
"""

from dataclasses import dataclass

import os
import signal
import subprocess

import dns.rcode
import dns.update
import pytest

from dnstap.common import ARTIFACTS, check_counts

import isctest
import isctest.mark

pytestmark = [
    isctest.mark.with_dnstap,
    pytest.mark.requires_zones_loaded("ns1", "ns2", "ns3", "ns4", "ns5"),
    pytest.mark.extra_artifacts(ARTIFACTS),
]


@dataclass
class Capture:
    proc: subprocess.Popen
    output: str

    def wait_for_counts(self, expected):
        """
        Make fstrm_capture flush its output and wait until the expected
        frames have been written.
        """

        def check():
            self.proc.send_signal(signal.SIGHUP)
            try:
                check_counts(self.output, expected)
            except subprocess.CalledProcessError:
                # dnstap-read failed on a partially written frame; try again.
                return False
            return True

        isctest.run.retry_with_timeout(check, 10)


@pytest.fixture(name="capture")
def capture_fixture(request, ns4):
    """
    Run fstrm_capture on ns4's dnstap socket for the duration of the test
    and make named connect to it.
    """
    output = f"dnstap.out.{request.node.originalname}"
    logfile = f"fstrm_capture.out.{request.node.originalname}"
    args = [
        os.environ["FSTRM_CAPTURE"],
        "-t",
        "protobuf:dnstap.Dnstap",
        "-u",
        "ns4/dnstap.out",
        "-w",
        output,
    ]
    with open(logfile, "wb") as log, subprocess.Popen(
        args, stdout=log, stderr=subprocess.STDOUT
    ) as proc:
        try:
            with isctest.log.WatchLogFromStart(logfile, timeout=10) as watcher:
                watcher.wait_for_line("socket path ns4/dnstap.out")
            ns4.rndc("dnstap -reopen")
            yield Capture(proc, output)
        finally:
            proc.terminate()


def query(ns4):
    msg = isctest.query.create("a.example.", "A")
    isctest.query.udp(msg, ns4.ip, expected_rcode=dns.rcode.SERVFAIL)


@isctest.mark.with_fstrm_capture
def test_unix_socket(ns4, capture):
    query(ns4)
    update = dns.update.Update("example")
    update.add("b.example.", 3600, "A", "10.10.10.10")
    ns4.nsupdate(update, expected_rcode=dns.rcode.NOTAUTH)
    capture.wait_for_counts({"UDP": 4, "CQ": 1, "CR": 1, "UQ": 1, "UR": 1})


@isctest.mark.with_fstrm_capture
def test_unix_socket_reopen(ns4, capture):
    """
    Check that named reconnects to a new listener on the socket after the
    previous one (from the test above) has gone away.
    """
    query(ns4)
    capture.wait_for_counts({"UDP": 2, "CQ": 1, "CR": 1})
