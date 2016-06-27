#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.19 2012/02/22 23:47:35 tbox Exp $

#
# Clean up after zone transfer tests.
#

rm -f dig.out.ns1 dig.out.ns2 dig.out.ns3 dig.out.ns4
rm -f dig.out.ns5 dig.out.ns6 dig.out.ns7
rm -f dig.out.soa.ns3
rm -f dig.out.msgsize
rm -f axfr.out
rm -f ns1/slave.db ns2/slave.db
rm -f ns1/edns-expire.db
rm -f ns2/example.db ns2/tsigzone.db ns2/example.db.jnl
rm -f ns3/example.bk ns3/tsigzone.bk ns3/example.bk.jnl
rm -f ns3/master.bk ns3/master.bk.jnl
rm -f ns4/named.conf ns4/nil.db ns4/root.db
rm -f ns6/*.db ns6/*.bk ns6/*.jnl
rm -f ns7/*.db ns7/*.bk ns7/*.jnl
rm -f ns8/large.db ns8/small.db

rm -f */named.memstats
rm -f */named.run
rm -f */ans.run
rm -f ns*/named.lock
rm -f ns2/mapped.db
rm -f ns3/mapped.bk
rm -f dig.out.?.*
