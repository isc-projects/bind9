# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.*
rm -f ns*/*.jnl
rm -f ns*/*.nzf
rm -f ns*/named.lock
rm -f ns*/named.memstats
rm -f ns*/named.run
rm -f ns1/*dom*example.db
rm -f ns2/__catz__*db
rm -f ns2/named.conf
rm -f ns3/dom{13,14}.example.db
rm -f nsupdate.out.*
rm -f ns{1,2,3}/catalog{1,2,3,4}.example.db
rm -rf ns2/zonedir
rm -f ns*/*.nzd ns*/*.nzd-lock
