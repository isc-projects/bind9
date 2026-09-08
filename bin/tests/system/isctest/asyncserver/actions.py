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

from dataclasses import dataclass

import asyncio
import logging

import dns.flags
import dns.message

from . import ResponseAction, _ConnectionTeardownRequested, _is_asyncserver_response


@dataclass
class DnsResponseSend(ResponseAction):
    """
    Action which yields a dns.message.Message response.

    The response may be sent with a delay if requested.

    Depending on the value of the `authoritative` property, this class may set
    the AA bit in the response (True), clear it (False), or not touch it at all
    (None).

    The message object is the source of truth: it is rendered to wire at send
    time, so any mutation made before it is yielded is reflected.  The one
    exception is a TSIG-signed response, which is sent from its already-rendered
    wire verbatim to preserve the signature; setting `authoritative` on such a
    response raises, since the AA change could not reach the signed wire.
    """

    response: dns.message.Message
    authoritative: bool | None = None
    delay: float = 0.0
    acknowledge_hand_rolled_response: bool = False

    async def perform(self) -> dns.message.Message | bytes | None:
        """
        Yield a potentially delayed response that is a dns.message.Message.
        """
        assert isinstance(self.response, dns.message.Message)
        if not (
            _is_asyncserver_response(self.response)
            or self.acknowledge_hand_rolled_response
        ):
            error = "The response you are trying to send was not created using "
            error += "AsyncDnsServer's response preparation methods. "
            error += "This will break features such as automatic AA flag "
            error += "and RCODE handling. If you need a fresh copy of a "
            error += "response, use `QueryContext.prepare_new_response` "
            error += "instead of `dns.message.make_response`. "
            error += "To acknowledge this and proceed anyway, set "
            error += "`acknowledge_hand_rolled_response=True` in "
            error += "DnsResponseSend's constructor."
            raise RuntimeError(error)

        if self.authoritative is not None:
            if self.response.tsig is not None and self.response.wire is not None:
                raise RuntimeError(
                    "DnsResponseSend(authoritative=...) has no effect on a "
                    "TSIG-signed, already-rendered response: it is sent from its "
                    "cached wire verbatim, so the AA-bit change would be silently "
                    "lost. Set the AA bit before signing the response."
                )
            if self.authoritative:
                self.response.flags |= dns.flags.AA
            else:
                self.response.flags &= ~dns.flags.AA
        if self.delay > 0:
            logging.info(
                "Delaying response (ID=%d) by %d ms",
                self.response.id,
                self.delay * 1000,
            )
            await asyncio.sleep(self.delay)
        return self.response


@dataclass
class BytesResponseSend(ResponseAction):
    """
    Action which yields a raw response that is a sequence of bytes.

    The response may be sent with a delay if requested.
    """

    response: bytes
    delay: float = 0.0

    async def perform(self) -> dns.message.Message | bytes | None:
        """
        Yield a potentially delayed response that is a sequence of bytes.
        """
        assert isinstance(self.response, bytes)
        if self.delay > 0:
            logging.info("Delaying raw response by %d ms", self.delay * 1000)
            await asyncio.sleep(self.delay)
        return self.response


@dataclass
class ResponseDrop(ResponseAction):
    """
    Action which does nothing - as if a packet was dropped.
    """

    async def perform(self) -> dns.message.Message | bytes | None:
        return None


@dataclass
class CloseConnection(ResponseAction):
    """
    Action which makes the server close the connection (TCP only).

    The connection may be closed with a delay if requested.
    """

    delay: float = 0.0

    async def perform(self) -> dns.message.Message | bytes | None:
        if self.delay > 0:
            logging.info("Waiting %.1fs before closing TCP connection", self.delay)
            await asyncio.sleep(self.delay)
        raise _ConnectionTeardownRequested
