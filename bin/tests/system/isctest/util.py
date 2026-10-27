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

from collections.abc import Iterator

import contextlib
import os

import dns.rrset
import dns.zone
import pytest

NS_PER_SEC = 1_000_000_000


def zone_contains(
    zone: dns.zone.Zone, rrset: dns.rrset.RRset, compare_ttl=False
) -> bool:
    """
    Check if a zone contains RRset
    """

    def compare_rrs(rr1, rrset):
        rr2 = next((other_rr for other_rr in rrset if rr1 == other_rr), None)
        if rr2 is None:
            return False
        if compare_ttl:
            return rr1.ttl == rr2.ttl
        return True

    for _, node in zone.nodes.items():
        for rdataset in node:
            for rr in rdataset:
                if compare_rrs(rr, rrset):
                    return True

    return False


def file_contents_contain(file, substr):
    with open(file, "r", encoding="utf-8") as fp:
        for line in fp:
            if f"{substr}" in line:
                return True
    return False


@contextlib.contextmanager
def newer_mtime(path: str | os.PathLike) -> Iterator[None]:
    """
    Make sure that `path`, rewritten inside the block, ends up with
    a modification time in a later second than it had before.

    named reloads a file only when its modification time is newer than the
    last load, and where file timestamps resolve whole seconds only (macOS,
    some file systems), a file rewritten within the same second is skipped as
    "older than last load". A file that did not exist before is left as is.
    """
    try:
        before: int | None = os.stat(path).st_mtime_ns
    except FileNotFoundError:
        before = None

    yield

    if before is None:
        return
    after = os.stat(path)
    if after.st_mtime_ns // NS_PER_SEC <= before // NS_PER_SEC:
        os.utime(path, ns=(after.st_atime_ns, before + NS_PER_SEC))


def param(*args, **kwargs):
    if "id" not in kwargs:
        kwargs["id"] = args[0]  # use first argument  as test ID
    return pytest.param(*args, **kwargs)
