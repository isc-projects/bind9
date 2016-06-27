#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

rm -f dig.out.*
rm -f ns*/named.lock
rm -f ns2/named.conf
rm -f ns3/example.db
rm -f ns3/named.conf
rm -f ns3/undelegated.db
rm -f ns4/sub.example.db
rm -f ns?/named.memstats
rm -f ns?/named.run
rm -f ns?/named_dump.db
rm -rf */*.signed
rm -rf */K*
rm -rf */dsset-*
rm -rf */trusted.conf
