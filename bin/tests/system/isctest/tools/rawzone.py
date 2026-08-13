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
Inspect the header of a zone file in raw format.

The header starts with three big-endian 32-bit words (format, version,
dump time); only format 2 is raw.  Version 1 and newer adds flags and,
when flag 0x02 is set, the source serial of the zone the file was
generated from.
"""

import argparse
import struct


def version(path: str) -> int | None:
    """Return the raw-format version of the zone file, or None if the
    file is not in raw format."""
    with open(path, "rb") as f:
        header = f.read(8)
    if len(header) < 8:
        return None
    fmt, ver = struct.unpack(">II", header)
    if fmt != 2:
        return None
    return ver


def source_serial(path: str) -> int | None:
    """Return the source serial recorded in the raw zone file, or None
    if there is none (not raw, version 0, or the serial is not set)."""
    with open(path, "rb") as f:
        header = f.read(20)
    if len(header) < 20:
        return None
    fmt, ver, _dumptime, flags, serial = struct.unpack(">IIIII", header)
    if fmt != 2 or ver < 1 or not flags & 2:
        return None
    return serial


def main() -> None:
    parser = argparse.ArgumentParser(prog="rawzone", description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    subparsers.add_parser("version").add_argument("path")
    subparsers.add_parser("sourceserial").add_argument("path")
    args = parser.parse_args()
    if args.subcommand == "version":
        result = version(args.path)
        print("not raw" if result is None else result)
    else:
        result = source_serial(args.path)
        print("UNSET" if result is None else result)


if __name__ == "__main__":
    main()
