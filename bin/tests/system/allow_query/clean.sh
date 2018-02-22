#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014-2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Clean up after allow query tests.
#

rm -f dig.out.*
rm -f ns2/named.conf ns2/controls.conf
rm -f */named.memstats
rm -f ns*/named.lock
rm -f ns*/named.run
