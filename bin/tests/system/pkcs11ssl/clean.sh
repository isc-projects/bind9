#!/bin/sh
#
# Copyright (C) 2014, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f K* ns1/K* keyset-* dsset-* ns1/*.db ns1/*.signed ns1/*.jnl
rm -f dig.out pin
rm -f ns1/*.key ns1/named.memstats
rm -f supported
rm -f ns*/named.lock
