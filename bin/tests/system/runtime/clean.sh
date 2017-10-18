#!/bin/sh
#
# Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns2/named.conf
rm -f */named.memstats
rm -f */named*.run
rm -f ns*/named.lock ns*/named*.pid ns*/other.lock
rm -f *.pid
rm -f rndc.out*
[ -d ns2/nope ] && chmod 755 ns2/nope
rm -rf ns2/nope
rm -f ns2/dir ns2/nopedir ns2/mkd ns2/nopemkd
