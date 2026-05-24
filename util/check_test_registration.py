# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.


import glob
import os
import sys

test_dir = sys.argv[1]
registered = sys.argv[2:]

for path in sorted(glob.glob(os.path.join(test_dir, "*_test.c"))):
    name = os.path.basename(path).removesuffix("_test.c")
    if name not in registered:
        print(
            f"Unit test file {os.path.basename(path)} is not registered"
            f" (add '{name}' to the list)",
            file=sys.stderr,
        )
        sys.exit(1)
