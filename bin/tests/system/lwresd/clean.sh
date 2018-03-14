#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Clean up after lwresd tests.
#
rm -f */named.memstats
rm -f */named.run
rm -f dig.out
rm -f lwresd1/lwresd.run.resolv
rm -f lwresd1/lwresd.run.lwresd
rm -f ns*/named.lock
rm -f lwresd*/lwresd.lock
rm -f lwresd*/lwresd.run
