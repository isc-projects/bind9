#!/usr/bin/env -S jq -rf

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

# Select baseline tag version for testing

.version
    | rtrimstr("-dev")
    | split(".")
    | {major: .[0], minor: .[1], patch: .[2]}
    | map_values(tonumber)
    # When testing a .0 release, compare it against the previous development
    # release (e.g., 9.19.0 and 9.18.0 should both be compared against 9.17.22).
    | if .patch == 0 then .minor - 1 - (.minor % 2) else .minor end
    | "v9.\(.)"
