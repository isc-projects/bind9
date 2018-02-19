#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2011-2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.* rndc.out.* ns1/named.conf
rm -f K* ns1/K*
rm -f */named.memstats
rm -f */named.run
rm -f ns1/_default.tsigkeys
rm -f ns*/named.lock
