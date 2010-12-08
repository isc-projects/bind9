#!/bin/sh
#
# Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: tests.sh,v 1.2 2010/12/08 02:46:15 marka Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +nocmd -p 5300"

for conf in conf/good*.conf
do
        echo "I:checking that $conf is accepted ($n)"
        ret=0
        $CHECKCONF "$conf" || ret=1
        n=`expr $n + 1`
        if [ $ret != 0 ]; then echo "I:failed"; fi
        status=`expr $status + $ret`
done

for conf in conf/bad*.conf
do
        echo "I:checking that $conf is rejected ($n)"
        ret=0
        $CHECKCONF "$conf" >/dev/null && ret=1
	n=`expr $n + 1`
        if [ $ret != 0 ]; then echo "I:failed"; fi
        status=`expr $status + $ret`
done

# Check the example. domain

echo "I: checking non-excluded AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-bad-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-good-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::1.2.3.4" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially excluded only AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded AAAA and non-mapped A lookup works ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-bad-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded only AAAA and mapped A lookup works ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-good-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only lookup works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only lookup works ($n)"
ret=0
$DIG $DIGOPTS a-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS a-and-aaaa.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A lookup works ($n)"
ret=0
$DIG $DIGOPTS a-not-mapped.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS mx-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA lookup works ($n)"
ret=0
$DIG $DIGOPTS non-existent.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-bad-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-good-a.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::1.2.3.4" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-and-aaaa.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-not-mapped.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-mx-only.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-non-existent.example. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the example. domain recursive only

echo "I: checking non-excluded AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:bbbb::1.2.3.4" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially excluded only AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded AAAA and non-mapped A lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded only AAAA and mapped A lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS partially-excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS a-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:bbbb::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS a-and-aaaa.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS a-not-mapped.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS mx-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS non-existent.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:bbbb::102:304" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-a-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:bbbb::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-a-and-aaaa.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-a-not-mapped.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-mx-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME lookup works, recursive only ($n)"
ret=0
$DIG $DIGOPTS cname-non-existent.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the example. domain recursive only w/o recursion

echo "I: checking non-excluded AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially excluded only AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec partially-excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee:" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded AAAA and non-mapped A lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec partially-excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee:" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking partially-excluded only AAAA and mapped A lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec partially-excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee:" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec a-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec a-and-aaaa.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec a-not-mapped.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec mx-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec non-existent.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-excluded-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-excluded-bad-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-excluded-good-a.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-aaaa-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-a-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-only.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-a-and-aaaa.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-a-not-mapped.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-mx-only.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME lookup works, recursive only +norec ($n)"
ret=0
$DIG $DIGOPTS +norec cname-non-existent.example. @10.53.0.1 -b 10.53.0.1 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the example. domain from non client

echo "I: checking non-excluded AAAA from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-bad-a.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS excluded-good-a.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS a-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS a-and-aaaa.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS a-not-mapped.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS mx-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS non-existent.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-bad-a.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-good-a.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-and-aaaa.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-a-not-mapped.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-mx-only.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.example." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME from non-client lookup works ($n)"
ret=0
$DIG $DIGOPTS cname-non-existent.example. @10.53.0.2 -b 10.53.0.3 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the signed. domain

echo "I: checking non-excluded AAAA lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS excluded-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS excluded-bad-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS excluded-good-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:304" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS a-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS a-and-aaaa.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS a-not-mapped.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS mx-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS non-existent.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-bad-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-excluded-good-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:304" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-a-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:305" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-a-and-aaaa.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-a-not-mapped.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.signed." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-mx-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.signed." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME lookup is signed zone works ($n)"
ret=0
$DIG $DIGOPTS cname-non-existent.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the signed. domain
echo "I: checking non-excluded AAAA lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec excluded-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec excluded-bad-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec excluded-good-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec a-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec a-and-aaaa.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec a-not-mapped.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec mx-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec non-existent.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-excluded AAAA via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-excluded-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::3" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded AAAA and non-mapped A via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-excluded-bad-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking excluded only AAAA and mapped A via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-excluded-good-a.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:eeee::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking AAAA only via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-aaaa-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::2" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A only via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-a-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "2001:aaaa::102:305" dig.out.ns2.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking A and AAAA via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-a-and-aaaa.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "2001::1" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-mapped A via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-a-not-mapped.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2" dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	a-not-mapped.signed." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking NODATA AAAA via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-mx-only.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
grep "CNAME	mx-only.signed." dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: checking non-existent AAAA via CNAME lookup is signed zone works with +dnssec ($n)"
ret=0
$DIG $DIGOPTS +dnssec cname-non-existent.signed. @10.53.0.2 -b 10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 2," dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
