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

import subprocess
import textwrap
import time

import isctest


def test_nsupdate_timeout(ns1):
    # `-v` forces TCP, `-t 1` forces timeout to 1 second, `-i` forces
    # interactive mode (as no tty would be detected here: `isatty()`
    # call would return 0).
    with subprocess.Popen(
        [isctest.vars.ALL["NSUPDATE"], "-v", "-t", "1", "-i"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        # Immediately add a RR, which its existence will be tested below.
        proc.stdin.write(textwrap.dedent(f"""\
            server {ns1.ip} {ns1.ports.dns}
            zone sample.
            update add sometext1.sample. 300 TXT "blah"
            send
        """))
        proc.stdin.flush()

        # Wait longer than the TCP connect timeout.
        time.sleep(2)

        # That one should not fail, as the TCP connect timeout
        # starts at `send` being sent.
        proc.stdin.write(textwrap.dedent(f"""\
            server {ns1.ip} {ns1.ports.dns}
            zone sample.
            update add sometext2.sample. 300 TXT "blah"
            send
        """))
        proc.stdin.flush()

        # Verify the one above didn't timeout.
        _, stderr = proc.communicate(timeout=10)
        assert proc.returncode == 0
        assert "timed out" not in stderr

        # Verify if records were updated.
        for name in ("sometext1.sample.", "sometext2.sample."):
            msg = isctest.query.create(name, "TXT")
            res = isctest.query.tcp(msg, ns1.ip)
            isctest.check.noerror(res)
            assert len(res.answer) == 1
