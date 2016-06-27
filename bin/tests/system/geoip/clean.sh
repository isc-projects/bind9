#!/bin/sh
#
# Copyright (C) 2013, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns2/named.conf
rm -f ns2/example*.db
rm -f dig.out.* rndc.out.*
rm -f data2/*dat
[ -d data2 ] && rmdir data2
rm -f ns?/named.run
rm -f ns?/named.memstats
rm -f ns*/named.lock
