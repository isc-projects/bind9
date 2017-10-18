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
echo "I: checking that named refuses to reconfigure if managed-keys-directory is set and not writable ($n)"
ret=0
cp -f ns2/named-alt4.conf ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig > rndc.out.$n 2>&1
grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
sleep 1
grep "managed-keys-directory '.*' is not writable" ns2/named.run > /dev/null 2>&1 || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that named refuses to reconfigure if managed-keys-directory is unset and working directory is not writable ($n)"
ret=0
cp -f ns2/named-alt5.conf ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig > rndc.out.$n 2>&1
grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
sleep 1
grep "working directory '.*' is not writable" ns2/named.run > /dev/null 2>&1 || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that named reconfigures if working directory is not writable but managed-keys-directory is ($n)"
ret=0
cp -f ns2/named-alt6.conf ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig > rndc.out.$n 2>&1
grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: shutting down existing named"
[ -s named4.pid ] && kill -15 `cat named4.pid` > /dev/null 2>&1
[ -s named5.pid ] && kill -15 `cat named5.pid` > /dev/null 2>&1
[ -s named6.pid ] && kill -15 `cat named6.pid` > /dev/null 2>&1

n=`expr $n + 1`
echo "I: checking that named refuses to start if managed-keys-directory is set and not writable ($n)"
ret=0
cd ns2
$NAMED -c named-alt4.conf -d 99 -g > named4.run 2>&1 &
sleep 2
grep "exiting (due to fatal error)" named4.run > /dev/null || ret=1
[ -s named4.pid ] && kill -15 `cat named4.pid` > /dev/null 2>&1
cd ..
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that named refuses to start if managed-keys-directory is unset and working directory is not writable ($n)"
ret=0
cd ns2
$NAMED -c named-alt5.conf -d 99 -g > named5.run 2>&1 &
sleep 2
grep "exiting (due to fatal error)" named5.run > /dev/null || ret=1
[ -s named5.pid ] && kill -15 `cat named5.pid` > /dev/null 2>&1
cd ..
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that named starts if managed-keys-directory is writable and working directory is not writable ($n)"
ret=0
cd ns2
$NAMED -c named-alt6.conf -d 99 -g > named6.run 2>&1 &
sleep 2
grep "exiting (due to fatal error)" named6.run > /dev/null || ret=1
[ -s named6.pid ] && kill -15 `cat named6.pid` > /dev/null 2>&1
cd ..
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
