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

import time


def retry_with_timeout(func, timeout, delay=1, msg=None):
    start_time = time.time()
    while time.time() < start_time + timeout:
        if func():
            return
        time.sleep(delay)
    if msg is None:
        msg = f"{func.__module__}.{func.__qualname__} timed out after {timeout} s"
    assert False, msg
