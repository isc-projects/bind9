#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

cp -f ns1/example1.db ns1/example.db
rm -f ns1/example.db.jnl ns2/example.bk ns2/example.bk.jnl
rm -f ns1/example2.db.jnl ns2/example2.bk ns2/example2.bk.jnl
cp -f ns3/nomaster.db ns3/nomaster1.db
rm -f Ksig0.example2.*

#
# SIG(0) required cryptographic support which may not be configured.
#
test -r $RANDFILE || $GENRANDOM 400 $RANDFILE 
keyname=`$KEYGEN  -q -r $RANDFILE -n HOST -a RSASHA1 -b 1024 -T KEY sig0.example2 2>/dev/null | $D2U`
if test -n "$keyname"
then
	cat ns1/example1.db $keyname.key > ns1/example2.db
	echo $keyname > keyname
else
	cat ns1/example1.db > ns1/example2.db
	rm -f keyname
fi
