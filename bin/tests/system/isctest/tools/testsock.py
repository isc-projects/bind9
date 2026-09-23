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
Check that the test network interfaces are up.

Try to bind() a UDP socket on each of the given addresses (IPv4 or IPv6).

When no address is specified, check the 10.53.0.* test addresses.
"""

from collections.abc import Iterable
from pathlib import Path

import argparse
import re
import socket
import sys

import dns.inet

# ifconfig.sh.in sets the test interfaces up; its max= setting is the
# authoritative count of the 10.53.0.* addresses.
IFCONFIG_SCRIPT = Path(__file__).resolve().parents[2] / "ifconfig.sh.in"


def check_addr(address: str, port: int = 0) -> None:
    """
    Try to bind a UDP socket to the given address and port; raise
    OSError on failure and ValueError for a malformed address.
    """
    try:
        family = dns.inet.af_for_address(address)
    except ValueError:
        raise ValueError(f"{address}: not an IPv4 or IPv6 address") from None
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((address, port))
        except OSError as exc:
            raise OSError(
                exc.errno, f"bind({address}, {port}): {exc.strerror}"
            ) from exc


def interface_ids() -> range:
    """
    Return the range of configured test interface ids, read from the
    max= setting in ifconfig.sh.in.
    """
    matches = re.findall(
        r"^max=(\d+)\s*$",
        IFCONFIG_SCRIPT.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if not matches:
        raise RuntimeError(f"could not find max IP address in {IFCONFIG_SCRIPT}")
    return range(1, int(matches[-1]) + 1)


def check_ipv4_interfaces(port: int = 0, server_id: int | None = None) -> None:
    """
    Check that the 10.53.0.* test interfaces (or just 10.53.0.<server_id>)
    are up and the given port can be bound on them; raise OSError on
    failure.
    """
    ids: Iterable[int]
    if server_id is not None:
        ids = [server_id]
    else:
        ids = interface_ids()
    for interface_id in ids:
        check_addr(f"10.53.0.{interface_id}", port)


def main() -> None:
    parser = argparse.ArgumentParser(prog="testsock", description=__doc__)
    parser.add_argument(
        "-p", "--port", type=int, default=0, help="UDP port to bind (default: any)"
    )
    parser.add_argument(
        "-i", "--id", type=int, help="check only the 10.53.0.<id> interface"
    )
    parser.add_argument(
        "address", nargs="*", help="addresses to check instead of 10.53.0.*"
    )
    args = parser.parse_args()
    try:
        if args.address:
            for address in args.address:
                check_addr(address, args.port)
        else:
            check_ipv4_interfaces(args.port, args.id)
    except (OSError, ValueError) as exc:
        sys.exit(f"testsock: {exc}")


if __name__ == "__main__":
    main()
