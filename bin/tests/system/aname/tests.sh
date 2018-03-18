#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

echo_i "minimal responses: default"

n=`expr $n + 1`
echo_i "check that ANAME query returns A and AAAA (if both are present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-both.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 3" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::a" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns A (if only A present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-a.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.2" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns AAAA (if only AAAA present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-aaaa.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::b" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

copy_setports ns1/named2.conf.in ns1/named.conf
$RNDCCMD 10.53.0.1 reconfig 2>&1 | sed 's/^/ns1 /' | cat_i

echo_i "minimal responses: yes"

n=`expr $n + 1`
echo_i "check that ANAME query returns A and AAAA (if both are present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-both.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 3" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::a" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns A (if only A present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-a.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.2" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns AAAA (if only AAAA present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-aaaa.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::b" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

copy_setports ns1/named3.conf.in ns1/named.conf
$RNDCCMD 10.53.0.1 reconfig 2>&1 | sed 's/^/ns1 /' | cat_i

echo_i "minimal responses: no"

n=`expr $n + 1`
echo_i "check that ANAME query returns A and AAAA (if both are present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-both.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 3" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::a" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns A (if only A present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-a.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.2" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "check that ANAME query returns AAAA (if only AAAA present) in additional ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.1 aname-aaaa.example aname > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "ADDITIONAL: 2" dig.out.test$n > /dev/null || ret=1
grep "flags:.*aa" dig.out.test$n > /dev/null || ret=1
grep "2001:db8::b" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
