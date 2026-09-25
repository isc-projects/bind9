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

from collections.abc import Sequence

import logging

import dns.rcode

from . import ControlCommand, ControllableAsyncDnsServer, ResponseHandler
from .context import QueryContext
from .handlers import IgnoreAllQueries


class ToggleResponsesCommand(ControlCommand):
    """
    Disable/enable sending responses from the server.
    """

    control_subdomain = "send-responses"

    def __init__(self) -> None:
        self._current_handler: IgnoreAllQueries | None = None

    def handle(
        self, args: list[str], server: ControllableAsyncDnsServer, qctx: QueryContext
    ) -> str | None:
        if len(args) != 1:
            logging.error("Invalid %s query %s", self, qctx.qname)
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            return "invalid query; use exactly one of 'enable' or 'disable' in QNAME"

        mode = args[0]

        if mode == "disable":
            if self._current_handler:
                return "sending responses already disabled"
            self._current_handler = IgnoreAllQueries()
            server.install_response_handler(self._current_handler, prepend=True)
            return "sending responses disabled"

        if mode == "enable":
            if not self._current_handler:
                return "sending responses already enabled"
            server.uninstall_response_handler(self._current_handler)
            self._current_handler = None
            return "sending responses enabled"

        logging.error("Unrecognized response sending mode '%s'", mode)
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        return f"unrecognized response sending mode '{mode}'"


class SwitchControlCommand(ControlCommand):
    """
    Switch the server's response handlers based on the control query.

    A sequence of response handlers is associated with each key.  When a
    control query is received, the server's response handlers are replaced
    with the sequence associated with the key extracted from the control
    query.
    """

    control_subdomain = "switch"

    def __init__(self, handler_mapping: dict[str, Sequence[ResponseHandler]]):
        self._handler_mapping = handler_mapping

    def handle(
        self, args: list[str], server: ControllableAsyncDnsServer, qctx: QueryContext
    ) -> str | None:
        if len(args) != 1 or args[0] not in self._handler_mapping:
            logging.error("Invalid %s query %s", self, qctx.qname)
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            return f"invalid query; exactly one of {list(self._handler_mapping.keys())} is expected in QNAME"

        server.replace_response_handlers(*self._handler_mapping[args[0]])
        return f"switched to handler set '{args[0]}'"
