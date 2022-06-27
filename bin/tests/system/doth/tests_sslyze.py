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
import pathlib
import subprocess

import pytest


def is_pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_sslyze_doh(sslyze_executable, named_httpsport):
    # Determine the PID of ns1.
    with open(pathlib.Path("ns1", "named.pid"), encoding="utf-8") as pidfile:
        pid = int(pidfile.read())

    # Ensure ns1 is alive before starting the loop below to avoid reporting
    # false positives.
    if not is_pid_alive(pid):
        pytest.skip(f"ns1 (PID: {pid}) is not running")

    # Run sslyze on ns1 in a loop with a limit of 30 iterations.  Interrupt the
    # test as soon as ns1 is determined to not be running any more.  Log sslyze
    # output.
    sslyze_args = [sslyze_executable, f"10.53.0.1:{named_httpsport}"]
    for i in range(0, 30):
        log_file = f"sslyze.log.doh.ns1.{named_httpsport}.{i + 1}"
        with open(log_file, "wb") as sslyze_log:
            # Run sslyze, logging stdout+stderr.  Ignore the exit code since
            # sslyze is only used for triggering crashes here rather than
            # actual TLS analysis.
            subprocess.run(
                sslyze_args,
                stdout=sslyze_log,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            # Ensure ns1 is still alive after each sslyze run.
            assert is_pid_alive(pid), f"ns1 (PID: {pid}) exited prematurely"
