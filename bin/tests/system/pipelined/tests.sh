#!/bin/sh
#
# Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

echo "I:check pipelined TCP queries"
ret=0
$PIPEQUERIES < input > raw || ret=1
awk '{ print $1 " " $5 }' < raw > output
sort < output > output-sorted
diff ref output-sorted || { ret=1 ; echo "I: diff sorted failed"; }
diff ref output > /dev/null && { ret=1 ; echo "I: diff out of order failed"; }
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# flush resolver so queries will be from others again
$RNDC -c ../common/rndc.conf -s 10.53.0.4 -p 9953 flush
sleep 1

echo "I:check pipelined TCP queries using mdig"
ret=0
$MDIG +noall +answer +vc -f input -p 5300 -b 10.53.0.4 @10.53.0.4 > raw.mdig
awk '{ print $1 " " $5 }' < raw.mdig > output.mdig
sort < output.mdig > output-sorted.mdig
diff ref output-sorted.mdig || { ret=1 ; echo "I: diff sorted failed"; }
diff ref output.mdig > /dev/null && { ret=1 ; echo "I: diff out of order failed"; }
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:check keep-response-order"
ret=0
$PIPEQUERIES ++ < inputb > rawb || ret=1
awk '{ print $1 " " $5 }' < rawb > outputb
diff refb outputb || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:check keep-response-order using mdig"
ret=0
$MDIG +noall +answer +vc -f inputb -p 5300 -b 10.53.0.7 @10.53.0.4 > rawb.mdig
awk '{ print $1 " " $5 }' < rawb.mdig > outputb.mdig
diff refb outputb.mdig || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
