#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2011, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns1/myftp.db
rm -f ns3/*.jnl ns3/mytest.db ns3/subtest.db
rm -f ns4/*.jnl ns4/*.db
rm -f */named.memstats
rm -f */named.conf
rm -f */named.run
rm -f */ans.run
rm -f dig.out dig.out1 dig.out2 dig.out3
rm -f ns3/large.db
rm -f ns*/named.lock
