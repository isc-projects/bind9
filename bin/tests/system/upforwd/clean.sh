#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: clean.sh,v 1.11 2011/10/30 23:46:15 tbox Exp $

#
# Clean up after zone transfer tests.
#

rm -f dig.out.ns1* dig.out.ns2 dig.out.ns1 dig.out.ns3 dig.out.ns1.after
rm -f ns1/*.jnl ns2/*.jnl ns3/*.jnl ns1/example.db ns2/*.bk ns3/*.bk
rm -f ns3/nomaster1.db
rm -f */named.memstats
rm -f */named.run
rm -f */ans.run
rm -f Ksig0.example2.*
rm -f keyname
rm -f ns*/named.lock
rm -f ns1/example2.db
