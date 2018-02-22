#!/bin/sh
#
# Copyright (C) 2008, 2012, 2014-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Clean up after zone transfer tests.
#

rm -f dig.out.*
rm -f ns2/example.db ns2/tsigzone.db ns2/example.db.jnl
rm -f */named.conf
rm -f */named.memstats
rm -f */named.run
rm -f ns*/named.lock
rm -f ns*/_default.nzf
rm -f ns*/_default.nzd*
