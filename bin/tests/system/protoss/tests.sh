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

status=0
n=1

echo_i "check PROTOSS option is logged correctly ($n)"
ret=0
nextpart ns2/named.run > /dev/null
$PYTHON protoss.py > /dev/null
nextpart ns2/named.run | grep "PROTOSS:" > protoss.out
lines=`cat protoss.out | wc -l`
[ "$lines" -eq 4 ] || ret=1
grep "org:1816793/ipv4:10.0.0.4" protoss.out > /dev/null || ret=1
grep "dev:deadbeef/org:1816793/ipv4:10.0.0.4" protoss.out > /dev/null || ret=1
grep "dev:deadbeef/org:1816793/ipv6:fe0f::1" protoss.out > /dev/null || ret=1
grep "va:30280231/ipv4:10.0.0.4/org:1816793" protoss.out > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
