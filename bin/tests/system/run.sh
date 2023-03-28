#!/usr/bin/python3
#
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

#
# Run system test using the pytest runner. This is a simple wrapper around
# pytest for convenience.
#

import argparse
import sys
import time

import pytest


def into_pytest_args(in_args):
    args = []
    if in_args.expression is None:
        try:
            import xdist
        except ImportError:
            pass
        else:
            # running all tests - execute in parallel
            args.extend(["-n", "auto"])
    else:
        args.extend(["-k", in_args.expression])
    if in_args.noclean:
        args.append("--noclean")
    if in_args.keep:
        print(
            "ERROR -k / --keep option not implemented.\n"
            "Please contact QA with your use-case and use ./legacy.run.sh in the meantime."
        )
        sys.exit(1)
    return args


def main():
    print(
        "----- WARNING -----\n"
        "Using pytest system test runner\n\n"
        'Please consider invoking "pytest" directly for more control:\n'
        "  single test:     pytest -k dns64\n"
        "  parallel tests:  pytest -n auto\n\n"
        "Alternately, use ./legacy.run.sh for the legacy system test runner.\n"
    )

    parser = argparse.ArgumentParser(
        description="Wrapper script for launching system tests"
    )
    parser.add_argument(
        "--noclean",
        action="store_true",
        help="don't clean tmpdir after test run",
    )
    parser.add_argument(
        "-k",
        "--keep",
        action="store_true",
        help="unused - not implemented",
    )
    parser.add_argument(
        "expression",
        type=str,
        nargs="?",
        help="select which test(s) to run",
    )

    args = into_pytest_args(parser.parse_args())
    print(f"$ pytest {' '.join(args)}\n" "---------------------------\n")

    time.sleep(2)  # force the user to stare at the warning message

    sys.exit(pytest.main(args))


if __name__ == "__main__":
    main()

# vim: set filetype=python :
