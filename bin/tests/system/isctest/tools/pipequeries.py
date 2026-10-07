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
Send A queries for the names read from stdin over a single TCP
connection, all of them before reading any response, and print the
answer sections in the order the responses arrive.
"""

import argparse
import random
import socket
import sys
import time

import dns.message
import dns.query
import dns.rcode

TIMEOUT = 30


def main() -> None:
    parser = argparse.ArgumentParser(prog="pipequeries", description=__doc__)
    parser.add_argument(
        "-s",
        "--server",
        default="127.0.0.1",
        help="server address (default: %(default)s)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=5300,
        help="server port (default: %(default)s)",
    )
    args = parser.parse_args()

    # Use sequential IDs from a random start, so that repeated runs do
    # not reuse the same ID sequence, just like ditch.py does.
    first_id = random.getrandbits(16)
    pending = {}
    for offset, qname in enumerate(sys.stdin.read().split()):
        msgid = (first_id + offset) & 0xFFFF
        query = dns.message.make_query(qname, "A", id=msgid)
        pending[msgid] = query

    expiration = time.time() + TIMEOUT
    with socket.create_connection((args.server, args.port), timeout=TIMEOUT) as sock:
        # socket.create_connection() leaves the socket in timeout mode,
        # where every recv() call would get its own TIMEOUT; switch to
        # non-blocking mode so that dns.query.send_tcp() and
        # dns.query.receive_tcp() honor the shared expiration deadline.
        sock.setblocking(False)
        for query in pending.values():
            dns.query.send_tcp(sock, query, expiration)

        while pending:
            response, _ = dns.query.receive_tcp(sock, expiration)
            sent = pending.get(response.id)
            if sent is None or not sent.is_response(response):
                sys.exit(f"I:unexpected response:\n{response}")
            del pending[response.id]
            if response.rcode() != dns.rcode.NOERROR:
                sys.exit(f"I:response rcode: {dns.rcode.to_text(response.rcode())}")
            count = response.section_count(dns.message.ANSWER)
            if count != 1:
                print(f"I:response answer count ({count}!=1)", file=sys.stderr)
            for rrset in response.answer:
                print(rrset.to_text(), flush=True)


if __name__ == "__main__":
    main()
