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

import asyncio
import gc

from isctest.asyncserver import AsyncDnsServer
from isctest.asyncserver.context import Peer
from isctest.asyncserver.handlers import IgnoreAllConnections


class IgnoreAllConnectionsThenCollectGarbage(IgnoreAllConnections):
    """
    Ignore every TCP connection and collect garbage a second after accepting
    it: unless the objects behind an ignored connection are kept alive on
    purpose, the collection destroys the task handling it.
    """

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: Peer
    ) -> None:
        await super().handle(reader, writer, peer)
        asyncio.get_running_loop().call_later(1, gc.collect)


def main() -> None:
    server = AsyncDnsServer()
    server.install_connection_handler(IgnoreAllConnectionsThenCollectGarbage())
    server.run()


if __name__ == "__main__":
    main()
