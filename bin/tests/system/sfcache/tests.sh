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

status=0
n=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +nocmd -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

echo_i "checking DNSSEC SERVFAIL is cached ($n)"
ret=0
$DIG $DIGOPTS +dnssec foo.example. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
rndc_dumpdb ns5 -all
awk '/Zone/{out=0} { if (out) print } /SERVFAIL/{out=1}' ns5/named_dump.db.test$n > sfcache.$n
grep "^; foo.example/A" sfcache.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking SERVFAIL is returned from cache ($n)"
ret=0
$DIG $DIGOPTS +dnssec foo.example. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking that +cd bypasses cache check ($n)"
ret=0
$DIG $DIGOPTS +dnssec +cd foo.example. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "switching to non-dnssec SERVFAIL tests"
ret=0
$RNDCCMD 10.53.0.5 flush 2>&1 | sed 's/^/I:ns5 /'
rndc_dumpdb ns5 -all
mv ns5/named_dump.db.test$n ns5/named_dump.db.test$n.1
awk '/SERVFAIL/ { next; out=1 } /Zone/ { out=0 } { if (out) print }' ns5/named_dump.db.test$n.1 > sfcache.$n.1
[ -s "sfcache.$n.1" ] && ret=1
echo_i "checking SERVFAIL is cached ($n)"
$DIG $DIGOPTS bar.example2. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
rndc_dumpdb ns5 -all
mv ns5/named_dump.db.test$n ns5/named_dump.db.test$n.2
awk '/Zone/{out=0} { if (out) print } /SERVFAIL/{out=1}' ns5/named_dump.db.test$n.2 > sfcache.$n.2
grep "^; bar.example2/A" sfcache.$n.2 > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking SERVFAIL is returned from cache ($n)"
ret=0
$DIG $DIGOPTS bar.example2. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking with +cd query ($n)"
ret=0
$DIG $DIGOPTS +cd bar.example2. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking with +dnssec query ($n)"
ret=0
$DIG $DIGOPTS +cd bar.example2. a @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
