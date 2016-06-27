#!/bin/sh
#
# Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

n=`expr $n + 1`
echo "Check that domain names that are too big when applying a search list entry are handled cleanly ($n)"
ret=0
l=012345678901234567890123456789012345678901234567890123456789012
t=0123456789012345678901234567890123456789012345678901234567890
d=$l.$l.$l.$t
$NSLOOKUP -port=5300 -domain=$d -type=soa example 10.53.0.1 > nslookup.out${n} || ret=1
grep "origin = ns1.example" nslookup.out${n} > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
