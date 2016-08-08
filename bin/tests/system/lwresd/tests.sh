#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011-2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.22 2012/02/03 23:46:58 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
echo "I:waiting for nameserver to load"
for i in 0 1 2 3 4 5 6 7 8 9
do
	ret=0
	for zone in . example1 e.example1 example2 10.10.10.in-addr.arpa \
	    ip6.int ip6.arpa
	do
		$DIG +tcp -p 5300 @10.53.0.1 soa $zone > dig.out
		grep "status: NOERROR" dig.out > /dev/null || ret=1
		grep "ANSWER: 1," dig.out > /dev/null || ret=1
	done
	test $ret = 0 && break
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:using resolv.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9 
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
./lwtest || ret=1
if [ $ret != 0 ]; then
	echo "I:failed"
fi
status=`expr $status + $ret`

$PERL $SYSTEMTESTTOP/stop.pl . lwresd1

mv lwresd1/lwresd.run lwresd1/lwresd.run.resolv

$PERL $SYSTEMTESTTOP/start.pl . lwresd1 -- "-X lwresd.lock -m record,size,mctx -c lwresd.conf -d 99 -g"

echo "I:using lwresd.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9 
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
./lwtest || ret=1
if [ $ret != 0 ]; then
	echo "I:failed"
fi
status=`expr $status + $ret`

$PERL $SYSTEMTESTTOP/stop.pl . lwresd1

mv lwresd1/lwresd.run lwresd1/lwresd.run.lwresd

$PERL $SYSTEMTESTTOP/start.pl . lwresd1 -- "-X lwresd.lock -m record,size,mctx -c nosearch.conf -d 99 -g"

echo "I:using nosearch.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9 
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
./lwtest -nosearch || ret=1
if [ $ret != 0 ]; then
	echo "I:failed"
fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
