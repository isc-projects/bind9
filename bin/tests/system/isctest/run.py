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
import subprocess
import time
from typing import Optional

import isctest.log
from isctest.compat import dns_rcode

import dns.message


def cmd(
    args,
    cwd=None,
    timeout=60,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    log_stdout=True,
    log_stderr=True,
    input_text: Optional[bytes] = None,
    raise_on_exception=True,
    env: Optional[dict] = None,
):
    """Execute a command with given args as subprocess."""
    isctest.log.debug(f"isctest.run.cmd(): {' '.join(args)}")

    def print_debug_logs(procdata):
        if procdata:
            if log_stdout and procdata.stdout:
                isctest.log.debug(
                    f"isctest.run.cmd(): (stdout)\n{procdata.stdout.decode('utf-8')}"
                )
            if log_stderr and procdata.stderr:
                isctest.log.debug(
                    f"isctest.run.cmd(): (stderr)\n{procdata.stderr.decode('utf-8')}"
                )

    if env is None:
        env = dict(os.environ)

    try:
        proc = subprocess.run(
            args,
            stdout=stdout,
            stderr=stderr,
            input=input_text,
            check=True,
            cwd=cwd,
            timeout=timeout,
            env=env,
        )
        print_debug_logs(proc)
        return proc
    except subprocess.CalledProcessError as exc:
        print_debug_logs(exc)
        isctest.log.debug(f"isctest.run.cmd(): (return code) {exc.returncode}")
        if raise_on_exception:
            raise exc
        return exc


class Dig:
    def __init__(self, base_params: str = ""):
        self.base_params = base_params

    def __call__(self, params: str) -> str:
        """Run the dig command with the given parameters and return the decoded output."""
        return cmd(
            [os.environ.get("DIG")] + f"{self.base_params} {params}".split(),
        ).stdout.decode("utf-8")


def retry_with_timeout(func, timeout, delay=1, msg=None):
    start_time = time.monotonic()
    exc_msg = None
    while time.monotonic() < start_time + timeout:
        exc_msg = None
        try:
            if func():
                return
        except AssertionError as exc:
            exc_msg = str(exc)
        time.sleep(delay)
    if exc_msg is not None:
        isctest.log.error(exc_msg)
    if msg is None:
        if exc_msg is not None:
            msg = exc_msg
        else:
            msg = f"{func.__module__}.{func.__qualname__} timed out after {timeout} s"
    assert False, msg


def get_named_cmdline(cfg_dir, cfg_file="named.conf"):
    cfg_dir = os.path.join(os.getcwd(), cfg_dir)
    assert os.path.isdir(cfg_dir)

    cfg_file = os.path.join(cfg_dir, cfg_file)
    assert os.path.isfile(cfg_file)

    named = os.getenv("NAMED")
    assert named is not None

    named_cmdline = [named, "-c", cfg_file, "-d", "99", "-g"]

    return named_cmdline


def get_custom_named_instance(assumed_ns, ports):
    # This test launches and monitors a named instance itself rather than using
    # bin/tests/system/start.pl, so manually defining a NamedInstance here is
    # necessary for sending RNDC commands to that instance. If this "custom"
    # instance listens on 10.53.0.3, use "ns3" as the identifier passed to
    # the NamedInstance constructor.
    named_ports = isctest.instance.NamedPorts(
        dns=ports["PORT"], rndc=ports["CONTROLPORT"]
    )
    instance = isctest.instance.NamedInstance(assumed_ns, named_ports)

    return instance


def assert_custom_named_is_alive(named_proc, resolver_ip):
    assert named_proc.poll() is None, "named isn't running"
    msg = dns.message.make_query("version.bind", "TXT", "CH")
    isctest.query.tcp(msg, resolver_ip, expected_rcode=dns_rcode.NOERROR)
