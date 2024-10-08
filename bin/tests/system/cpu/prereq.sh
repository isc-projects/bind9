#!/bin/sh

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

. ../conf.sh

command -v cpuset >/dev/null || command -v numactl >/dev/null || command -v taskset >/dev/null || {
  echo_i "This test requires cpuset, numactl, or taskset." >&2
  exit 255
}

exit 0
