#!/bin/sh
#
# Copyright (C) 2005-2007, 2012, 2014, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Clean up after tsig tests.
#

rm -f dig.out.*
rm -f */named.memstats
rm -f */named.run
rm -f ns*/named.lock
rm -f Kexample.net.*
rm -f keygen.out?
