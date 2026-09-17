#!/usr/bin/python3

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

from typing import NamedTuple

import os
from pathlib import Path
import re

from .log import WatchLogFromStart, WatchLogFromHere
from .run import CmdResult, EnvCmd
from .text import TextFile


class NamedPorts(NamedTuple):
    dns: int = 53
    rndc: int = 953


class NamedInstance:
    """
    A class representing a `named` instance used in a system test.

    This class is expected to be instantiated as part of the `servers` fixture:

    ```python
    def test_foo(servers):
        servers["ns1"].rndc("status")
    ```
    """

    def __init__(
        self,
        identifier: str,
        ports: NamedPorts = NamedPorts(),
    ) -> None:
        """
        `identifier` must be an `ns<X>` string, where `<X>` is an integer
        identifier of the `named` instance this object should represent.

        `ports` is the `NamedPorts` instance listing the UDP/TCP ports on which
        this `named` instance is listening for various types of traffic (both
        DNS traffic and RNDC commands).
        """
        self.ip = self._identifier_to_ip(identifier)
        self.ports = ports
        self.log = TextFile(os.path.join(identifier, "named.run"))

        self._rndc_conf = Path("../_common/rndc.conf").absolute()
        self._rndc = EnvCmd("RNDC", self.rndc_args)

    @property
    def rndc_args(self) -> str:
        """
        Base arguments for calling RNDC to control the instance.
        """
        return f"-c {self._rndc_conf} -s {self.ip} -p {self.ports.rndc}"

    @staticmethod
    def _identifier_to_ip(identifier: str) -> str:
        regex_match = re.match(r"^ns(?P<index>[0-9]{1,2})$", identifier)
        if not regex_match:
            raise ValueError("Invalid named instance identifier" + identifier)
        return "10.53.0." + regex_match.group("index")

    def rndc(self, command: str, timeout=10, **kwargs) -> CmdResult:
        """
        Send `command` to this named instance using RNDC.  Return the server's
        response.

        To suppress exceptions, redirect outputs, control logging change
        timeout etc. use keyword arguments which are passed to
        isctest.cmd.run().
        """
        return self._rndc(command, timeout=timeout, **kwargs)

    def watch_log_from_start(
        self, timeout: float = WatchLogFromStart.DEFAULT_TIMEOUT
    ) -> WatchLogFromStart:
        """
        Return an instance of the `WatchLogFromStart` context manager for this
        `named` instance's log file.
        """
        return WatchLogFromStart(self.log.path, timeout)

    def watch_log_from_here(
        self, timeout: float = WatchLogFromHere.DEFAULT_TIMEOUT
    ) -> WatchLogFromHere:
        """
        Return an instance of the `WatchLogFromHere` context manager for this
        `named` instance's log file.
        """
        return WatchLogFromHere(self.log.path, timeout)

    def reconfigure(self, **kwargs) -> CmdResult:
        """
        Reconfigure this named `instance` and wait until reconfiguration is
        finished.
        """
        with self.watch_log_from_here() as watcher:
            cmd = self.rndc("reconfig", **kwargs)
            watcher.wait_for_line("any newly configured zones are now loaded")
        return cmd
