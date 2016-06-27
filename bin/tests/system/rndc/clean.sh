#!/bin/sh
#
# Copyright (C) 2011-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f ns2/nil.db ns2/other.db ns2/static.db ns2/*.jnl
rm -f ns2/session.key
rm -f ns2/named.stats
rm -f ns3/named_dump.db
rm -f ns*/named.memstats
rm -f ns*/named.run
rm -f ns4/*.conf
rm -f rndc.status
rm -f rndc.output.test*
rm -f dig.out.test*
rm -f ns*/named.lock
rm -f ns4/*.nta
rm -f ns6/named.conf
rm -f ns6/huge.zone.db
