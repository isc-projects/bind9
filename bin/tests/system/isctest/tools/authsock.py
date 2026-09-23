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
Mock authorization daemon for update-policy "external" rules.

Listen on a Unix stream socket and answer every update-policy check
named sends: allow the update when it is for the one RR type given on
the command line, deny it for any other.  Log each request and the
decision on stdout; tests start the daemon in the background and grep
that log.

The request and reply formats are documented in the ARM under the
"external" update-policy rule (doc/arm/reference.rst) and produced by
dns_ssu_external_match() in lib/dns/ssu_external.c.  This tool speaks
protocol version 1.  The reply is a 4-byte integer in network byte
order: 0 denies the update and 1 allows it; 2 is sent for a malformed
request, which named also treats as a denial.
"""

import argparse
import os
import signal
import socket
import struct

VERSION = 1
HEADER = struct.Struct("!II")  # protocol version, total request length
WORD = struct.Struct("!I")
# Shortest possible request: header, five empty NUL-terminated strings
# and an empty TKEY token.
MIN_REQUEST_LEN = HEADER.size + 5 + WORD.size
REPLY_DENY = WORD.pack(0)
REPLY_ALLOW = WORD.pack(1)
REPLY_ERROR = WORD.pack(2)


def parse_request(body: bytes) -> tuple[list[str], bytes]:
    """
    Split a request body, everything after the version and length
    header, into its fields as the ARM lays them out: signer, name,
    TCP source address, rdata type and key as NUL-terminated strings,
    then the TKEY token length (4 bytes, network byte order) and the
    token, which fills the rest of the body.  Raise ValueError if the
    body does not have that shape.
    """
    fields = []
    rest = body
    for _ in range(5):
        value, sep, rest = rest.partition(b"\0")
        if not sep:
            raise ValueError("fewer than five NUL-terminated strings")
        fields.append(value.decode())
    if len(rest) < WORD.size:
        raise ValueError("missing TKEY token length")
    (token_len,) = WORD.unpack_from(rest)
    token = rest[WORD.size :]
    if len(token) != token_len:
        raise ValueError(f"TKEY token length {token_len} != {len(token)}")
    return fields, token


def authorize(rdtype: str, allowed_type: str) -> bytes:
    """
    Allow the update if it is for the one permitted RR type, deny it
    otherwise.  Return the packed reply.
    """
    if rdtype == allowed_type:
        print(f"allowed type {rdtype} == {allowed_type}", flush=True)
        return REPLY_ALLOW
    print(f"disallowed type {rdtype} != {allowed_type}", flush=True)
    return REPLY_DENY


def handle_request(conn: socket.socket, allowed_type: str) -> None:
    """
    Answer one request on an accepted connection.
    """
    header = conn.recv(HEADER.size, socket.MSG_WAITALL)
    if len(header) < HEADER.size:
        print(f"Short request header: {header.hex()}", flush=True)
        conn.sendall(REPLY_ERROR)
        return
    version, req_len = HEADER.unpack(header)
    if version != VERSION or req_len < MIN_REQUEST_LEN:
        print(f"Badly formatted request: {header.hex()}", flush=True)
        conn.sendall(REPLY_ERROR)
        return

    body = conn.recv(req_len - HEADER.size, socket.MSG_WAITALL)
    if len(body) + HEADER.size != req_len:
        print(f"Length mismatch {req_len} {len(body) + HEADER.size}", flush=True)
        conn.sendall(REPLY_ERROR)
        return

    try:
        (signer, name, addr, rdtype, key), token = parse_request(body)
    except ValueError as exc:
        print(f"Badly formatted request: {exc}: {body.hex()}", flush=True)
        conn.sendall(REPLY_ERROR)
        return
    print(
        f"version={version} signer={signer} name={name} addr={addr} "
        f"type={rdtype} key={key} key_data_len={len(token)}",
        flush=True,
    )
    conn.sendall(authorize(rdtype, allowed_type))


def serve(path: str, allowed_type: str) -> None:
    """
    Listen on the Unix socket at path and answer requests forever.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        server.listen()
        os.chmod(path, 0o777)
        while True:
            conn, _ = server.accept()
            with conn:
                handle_request(conn, allowed_type)


def main() -> None:
    parser = argparse.ArgumentParser(prog="authsock", description=__doc__)
    parser.add_argument("--path", required=True, help="Unix socket path to listen on")
    parser.add_argument(
        "--type", default="A", help="the one RR type to allow (default: %(default)s)"
    )
    parser.add_argument(
        "--pidfile", default="authsock.pid", help="where to write the process id"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="exit after this many seconds (default: run until killed)",
    )
    args = parser.parse_args()

    with open(args.pidfile, "w", encoding="utf-8") as pidfile:
        print(os.getpid(), file=pidfile)
    if args.timeout:
        # The default SIGALRM disposition terminates the process.
        signal.alarm(args.timeout)
    serve(args.path, args.type)


if __name__ == "__main__":
    main()
