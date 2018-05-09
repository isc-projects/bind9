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

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"
CLEANQL="rm -f ans2/query.log"
status=0
n=0

n=`expr $n + 1`
echo_i "query for .good is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.3 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.good. @10.53.0.3 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.good." | diff ans2/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.3 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.3 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.bad." | diff ans2/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .slow is not minimized when qname-minimization is off ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.3 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.slow. @10.53.0.3 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
echo "A icky.icky.icky.ptang.zoop.boing.slow." | diff ans2/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .good is properly minimized when qname-minimization is on ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.4 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.good. @10.53.0.4 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.good.
NS zoop.boing.good.
NS ptang.zoop.boing.good.
NS icky.ptang.zoop.boing.good.
NS icky.icky.ptang.zoop.boing.good.
A icky.icky.icky.ptang.zoop.boing.good.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad fails when qname-minimization is on and in strict mode ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.4 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.4 > dig.out.test$n
grep "status: NXDOMAIN" dig.out.test$n > /dev/null || ret=1
echo "NS boing.bad." | diff ans2/query.log - > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .bad succeds when qname-minimization is on and not in strict mode ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.5 flush
$DIG $DIGOPTS icky.icky.icky.ptang.zoop.boing.bad. @10.53.0.5 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS boing.bad.
NS zoop.boing.bad.
NS ptang.zoop.boing.bad.
NS icky.ptang.zoop.boing.bad.
NS icky.icky.ptang.zoop.boing.bad.
A icky.icky.icky.ptang.zoop.boing.bad.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "query for .ip6.arpa succeds and skips on boundaries when qname-minimization is on ($n)"
ret=0
$CLEANQL
$RNDCCMD 10.53.0.5 flush
$DIG $DIGOPTS -x 2001:4f8::1 @10.53.0.4 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
cat << __EOF | diff ans2/query.log - > /dev/null || ret=1
NS 1.0.0.2.ip6.arpa.
NS 8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
NS 0.0.0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
PTR 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.4.0.1.0.0.2.ip6.arpa.
__EOF
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
