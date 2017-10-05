#!/bin/sh
#
# Copyright (C) 2010, 2012-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.*
rm -f rndc.out*
rm -f showzone.out*
rm -f zonestatus.out*
rm -f ns2/named.conf
rm -f */named.memstats
rm -f ns1/*.nzf ns1/*.nzf~
rm -f ns1/*.nzd ns1/*.nzd-lock
rm -f ns2/*.nzf ns2/*.nzf~
rm -f ns2/*.nzd ns2/*.nzd-lock
rm -f ns3/*.nzf ns3/*.nzf~
rm -f ns3/*.nzd ns3/*.nzd-lock
rm -f ns2/core*
rm -f ns2/inline.db.jbk
rm -f ns2/inline.db.signed
rm -f ns2/inlineslave.bk*
rm -rf ns2/new-zones
rm -f ns*/named.lock
rm -f ns*/named.run
rm -f ns2/nzf-*
rm -f ns3/named.conf
rm -f ns3/*.nzf ns3/*.nzf~
rm -f ns3/*.nzd ns3/*.nzd-lock
rm -f ns3/inlineslave.db
rm -f ns1/redirect.db
rm -f ns2/redirect.db
rm -f ns2/redirect.bk
rm -f ns3/redirect.db
