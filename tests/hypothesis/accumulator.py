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
A minimal model test for a stateful uint64 accumulator.
"""

import os
import sys

from isc_hypothesis import RestartingProtobufServer

try:
    from hypothesis import example, given, settings
    from hypothesis import strategies as st

    import accumulator_pb2 as proto  # pylint: disable=import-error
except ModuleNotFoundError as error:
    print(f"skipping accumulator hypothesis tests: {error}", file=sys.stderr)
    sys.exit(77)

UINT64_MAX = 2**64 - 1
server = None


@settings(max_examples=300, deadline=None, derandomize=True)
@given(
    initial=st.integers(0, UINT64_MAX),
    changes=st.lists(st.integers(-127, 127), max_size=100),
)
@example(initial=0, changes=[-1, 1])
@example(initial=UINT64_MAX, changes=[1, -1])
@example(initial=42, changes=[0, 10, -3, -7])
def test_accumulator(initial, changes):
    # Reset between examples, while retaining state between commands.
    expected = initial
    assert server.command(proto.Request(reset=initial)).value == expected
    for change in changes:
        request = (
            proto.Request(add=change)
            if change >= 0
            else proto.Request(subtract=-change)
        )
        # Unsigned C arithmetic wraps modulo 2**64.
        expected = (expected + change) & UINT64_MAX
        assert server.command(request).value == expected


if __name__ == "__main__":
    with RestartingProtobufServer(
        os.environ["ACCUMULATOR_SERVER"], proto.Response
    ) as server:
        test_accumulator()  # pylint: disable=no-value-for-parameter
        print("test_accumulator: passed", flush=True)
