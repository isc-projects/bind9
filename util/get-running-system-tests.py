#!/usr/bin/env python3

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

import psutil

for pid in psutil.pids():
    try:
        environ = psutil.Process(pid).environ()
        if "PYTEST_CURRENT_TEST" in environ:
            name = psutil.Process(pid).name()
            print(
                f'pytest process {name}/{pid} running: {environ["PYTEST_CURRENT_TEST"]}'
            )
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
