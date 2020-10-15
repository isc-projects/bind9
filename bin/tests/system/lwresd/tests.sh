#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

common_options="-D lwresd-lwresd1 -X lwresd.lock -m record,size,mctx -T clienttest -d 99 -g -U 4 -i lwresd.pid -P 9210 -p 5300"

status=0
echo_i "waiting for nameserver to load"
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
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "using resolv.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
$LWTEST || ret=1
if [ $ret != 0 ]; then
	echo_i "failed"
fi
status=`expr $status + $ret`

$PERL $SYSTEMTESTTOP/stop.pl lwresd lwresd1

mv lwresd1/lwresd.run lwresd1/lwresd.run.resolv

$PERL $SYSTEMTESTTOP/start.pl --restart lwresd lwresd1 -- "-c lwresd.conf $common_options"

echo_i "using lwresd.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
$LWTEST || ret=1
if [ $ret != 0 ]; then
	echo_i "failed"
fi
status=`expr $status + $ret`

$PERL $SYSTEMTESTTOP/stop.pl lwresd lwresd1

mv lwresd1/lwresd.run lwresd1/lwresd.run.lwresd

$PERL $SYSTEMTESTTOP/start.pl --restart lwresd lwresd1 -- "-c nosearch.conf $common_options"

echo_i "using nosearch.conf"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	grep ' running$' lwresd1/lwresd.run > /dev/null && break
	sleep 1
done
$LWTEST -nosearch || ret=1
if [ $ret != 0 ]; then
	echo_i "failed"
fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
