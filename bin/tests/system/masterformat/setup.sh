#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

$SHELL clean.sh

copy_setports ns1/named.conf.in ns1/named.conf
copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns3/named.conf.in ns3/named.conf

cp ns1/example.db ns2/
cp ns2/formerly-text.db.in ns2/formerly-text.db
cp ns1/large.db.in ns1/large.db
awk 'END {
	 for (i = 0; i < 500; i++ ) { print "500-txt TXT", i; }
	 for (i = 0; i < 1000; i++ ) { print "1000-txt TXT", i; }
	 for (i = 0; i < 2000; i++ ) { print "2000-txt TXT", i; }
}' </dev/null >>ns1/large.db
cp ns1/huge.db.in ns1/huge.db
awk 'END {
	 for (i = 0; i < 500; i++ ) { print "500-txt TXT", i; }
	 for (i = 0; i < 1000; i++ ) { print "1000-txt TXT", i; }
	 for (i = 0; i < 2000; i++ ) { print "2000-txt TXT", i; }
	 for (i = 0; i < 2050; i++ ) { print "2050-txt TXT", i; }
}' </dev/null >>ns1/huge.db
cp ns1/uber.db.in ns1/uber.db
awk 'END {
	 for (i = 0; i < 500; i++ ) { print "500-txt TXT", i; }
	 for (i = 0; i < 1000; i++ ) { print "1000-txt TXT", i; }
	 for (i = 0; i < 2000; i++ ) { print "2000-txt TXT", i; }
	 for (i = 0; i < 2050; i++ ) { print "2050-txt TXT", i; }
	 for (i = 0; i < 2100; i++ ) { print "2100-txt TXT", i; }
}' </dev/null >>ns1/uber.db
cp ns1/many.db.in ns1/many.db
for ntype in $(seq 65280 65534); do
  echo "m TYPE${ntype} \# 0"
done >>ns1/many.db
echo "m TXT bunny" >>ns1/many.db
cd ns1 && $SHELL compile.sh
