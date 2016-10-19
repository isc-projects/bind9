#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.25 2007/06/19 23:47:07 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Perform tests
#

count=0
ticks=0
while [ $count != 300 ]; do
        if [ $ticks = 1 ]; then
	        echo "I:Changing test zone..."
		cp -f ns1/changing2.db ns1/changing.db
		if [ ! "$CYGWIN" ]; then
			$KILL -HUP `cat ns1/named.pid`
		else
			$RDNC -c ../common/rndc.conf -s 10.53.0.1 \
			    -p 9953 reloade > /dev/null 2>&1
		fi
	fi
	sleep 1
	ticks=`expr $ticks + 1`
	seconds=`expr $ticks \* 1`
	if [ $ticks = 360 ]; then
		echo "I:Took too long to load zones"
		exit 1
	fi
	count=`cat ns2/zone*.bk | grep xyzzy | wc -l`
	echo "I:Have $count zones up in $seconds seconds"
done

status=0

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	zone000099.example. @10.53.0.1 axfr -p 5300 > dig.out.ns1 || status=1
grep ";" dig.out.ns1

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	zone000099.example. @10.53.0.2 axfr -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$PERL ../digcomp.pl dig.out.ns1 dig.out.ns2 || status=1

sleep 15

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.changing. @10.53.0.1 a -p 5300 > dig.out.ns1 || status=1
grep ";" dig.out.ns1

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.changing. @10.53.0.2 a -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$PERL ../digcomp.pl dig.out.ns1 dig.out.ns2 || status=1

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
