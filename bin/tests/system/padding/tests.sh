#!/bin/sh
#
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

n=0
status=0

getcookie() {
	awk '$2 == "COOKIE:" {
		print $3;
	}' < $1
}

echo "I:checking that dig handles padding ($n)"
ret=0
n=`expr $n + 1`
$DIG +qr +padding=128 foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null || ret=1
grep "; QUERY SIZE: 128" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that dig added padding ($n)"
ret=0
n=`expr $n + 1`
$RNDC  -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats
grep "EDNS padding option received" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that padding is added for TCP responses ($n)"
ret=0
n=`expr $n + 1`
$DIG +vc +padding=128 foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null || ret=1
grep "rcvd: 128" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that padding is added to valid cookie responses ($n)"
ret=0
n=`expr $n + 1`
$DIG +cookie foo.example @10.53.0.2 -p 5300 > dig.out.testc
cookie=`getcookie dig.out.testc`
$DIG +cookie=$cookie +padding=128 foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null || ret=1
grep "rcvd: 128" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that padding must be requested (TCP) ($n)"
ret=0
n=`expr $n + 1`
$DIG +vc foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that padding must be requested (valid cookie) ($n)"
ret=0
n=`expr $n + 1`
$DIG +cookie=$cookie foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that padding can be filtered out ($n)"
ret=0
n=`expr $n + 1`
$DIG +vc +padding=128 -b 10.53.0.8 foo.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "; PAD" dig.out.test$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that a TCP and padding server config enables padding ($n)"
ret=0
n=`expr $n + 1`
$RNDC  -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats
opad=`grep  "EDNS padding option received" ns2/named.stats | \
    tail -1 | awk '{ print $1}'`
$DIG foo.example @10.53.0.3 -p 5300 > dig.out.test$n
$RNDC  -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats
npad=`grep  "EDNS padding option received" ns2/named.stats | \
    tail -1 | awk '{ print $1}'`
if [ "$opad" -eq "$npad" ]; then ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that a padding server config should enforce TCP ($n)"
ret=0
n=`expr $n + 1`
$RNDC  -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats
opad=`grep  "EDNS padding option received" ns2/named.stats | \
    tail -1 | awk '{ print $1}'`
$DIG foo.example @10.53.0.4 -p 5300 > dig.out.test$n
$RNDC  -c ../common/rndc.conf -s 10.53.0.2 -p 9953 stats
npad=`grep  "EDNS padding option received" ns2/named.stats | \
    tail -1 | awk '{ print $1}'`
if [ "$opad" -ne "$npad" ]; then ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking that zero-length padding option has no effect ($n)"
ret=0
n=`expr $n + 1`
$DIG +qr +ednsopt=12 foo.example @10.53.0.2 -p 5300 > dig.out.test$n.1
grep "; PAD" dig.out.test$n.1 > /dev/null || ret=1
$DIG +qr +ednsopt=12:00 foo.example @10.53.0.2 -p 5300 > dig.out.test$n.2
grep "; PAD" dig.out.test$n.2 > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
