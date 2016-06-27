# Copyright (C) 2014-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

n=`expr $n + 1`
echo "I:verifying that named started normally ($n)"
ret=0
[ -s ns2/named.pid ] || ret=1
grep "unable to listen on any configured interface" ns2/named.run > /dev/null && ret=1
grep "another named process" ns2/named.run > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:verifying that named checks for conflicting listeners ($n)"
ret=0
(cd ns2; $NAMED -c named-alt1.conf -D ns2-extra-1 -X other.lock -m record,size,mctx -d 99 -g -U 4 >> named2.run 2>&1 & )
sleep 2
grep "unable to listen on any configured interface" ns2/named2.run > /dev/null || ret=1
[ -s ns2/named2.pid ] && kill -15 `cat ns2/named2.pid`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:verifying that named checks for conflicting named processes ($n)"
ret=0
(cd ns2; $NAMED -c named-alt2.conf -D ns2-extra-2 -X named.lock -m record,size,mctx -d 99 -g -U 4 >> named3.run 2>&1 & )
sleep 2
grep "another named process" ns2/named3.run > /dev/null || ret=1
[ -s ns2/named3.pid ] && kill -15 `cat ns2/named3.pid`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:verifying that 'lock-file none' disables process check ($n)"
ret=0
(cd ns2; $NAMED -c named-alt3.conf -D ns2-extra-3 -m record,size,mctx -d 99 -g -U 4 >> named4.run 2>&1 & )
sleep 2
grep "another named process" ns2/named4.run > /dev/null && ret=1
[ -s ns2/named4.pid ] && kill -15 `cat ns2/named4.pid`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`


echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
