#!/usr/bin/python3

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

from dnssec_nsec3.ans1 import common, f025, f055
from isctest.asyncserver import AsyncDnsServer


def main() -> None:
    keys = common.load_keys()
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handler(f025.F025Handler(keys))
    server.install_response_handler(f055.F055Handler(keys))
    server.run()


if __name__ == "__main__":
    main()
