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

# Test of include statement with glob expression.


SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noadd +nostats -p ${PORT}"

status=0
n=0

# Test 1 - check if zone1 was loaded.
n=`expr $n + 1`
echo_i "checking glob include of zone1 config ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 zone1.com. a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^zone1.com.' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

# Test 2 - check if zone2 was loaded.
n=`expr $n + 1`
echo_i "checking glob include of zone2 config ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 zone2.com. a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^zone2.com.' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

# Test 3 - check if standard file path (no magic chars) works.
n=`expr $n + 1`
echo_i "checking include of standard file path config ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 mars.com. a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^mars.com.' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
