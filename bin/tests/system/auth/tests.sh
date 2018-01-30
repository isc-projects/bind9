#!/bin/sh
#
# Copyright (C) 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp"

status=0
n=0

n=`expr $n + 1`
echo "I:wait for zones to finish transfering to ns2 ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
  ret=0
  for zone in example.com example.net
  do
    $DIG $DIGOPTS -p 5300 @10.53.0.2 soa $zone > dig.out.test$n || ret=1
    grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
  done
  [ $ret -eq 0 ] && break
  sleep 1
done
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

#
# If recursion is unrequested or unavailable, then cross-zone CNAME records
# should not be followed. If both requested and available, they should be.
#
n=`expr $n + 1`
echo "I:check that cross-zone CNAME record does not return target data (rd=0/ra=0) ($n)"
ret=0
$DIG $DIGOPTS +norec -p 5300 @10.53.0.1 www.example.com > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa;" dig.out.test$n > /dev/null || ret=1
grep "www.example.com.*CNAME.*server.example.net" dig.out.test$n > /dev/null || ret=1
grep "server.example.net.*A.*10.53.0.100" dig.out.test$n > /dev/null && ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that cross-zone CNAME record does not return target data (rd=1/ra=0) ($n)"
ret=0
$DIG $DIGOPTS +rec -p 5300 @10.53.0.1 www.example.com > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa rd;" dig.out.test$n > /dev/null || ret=1
grep "www.example.com.*CNAME.*server.example.net" dig.out.test$n > /dev/null || ret=1
grep "server.example.net.*A.*10.53.0.100" dig.out.test$n > /dev/null && ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that cross-zone CNAME record does not return target data (rd=0/ra=1) ($n)"
ret=0
$DIG $DIGOPTS +norec -p 5300 @10.53.0.2 www.example.com > dig.out.test$n || ret=1
grep "ANSWER: 1," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa ra;" dig.out.test$n > /dev/null || ret=1
grep "www.example.com.*CNAME.*server.example.net" dig.out.test$n > /dev/null || ret=1
grep "server.example.net.*A.*10.53.0.100" dig.out.test$n > /dev/null && ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that cross-zone CNAME records returns target data (rd=1/ra=1) ($n)"
ret=0
$DIG $DIGOPTS -p 5300 @10.53.0.2 www.example.com > dig.out.test$n || ret=1
grep "ANSWER: 2," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa rd ra;" dig.out.test$n > /dev/null || ret=1
grep "www.example.com.*CNAME.*server.example.net" dig.out.test$n > /dev/null || ret=1
grep "server.example.net.*A.*10.53.0.100" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

#
# In-zone CNAME records should always be followed regardless of RD and RA.
#
n=`expr $n + 1`
echo "I:check that in-zone CNAME records returns target data (rd=0/ra=0) ($n)"
ret=0
$DIG $DIGOPTS +norec -p 5300 @10.53.0.1 inzone.example.com > dig.out.test$n || ret=1
grep "ANSWER: 2," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa;" dig.out.test$n > /dev/null || ret=1
grep "inzone.example.com.*CNAME.*a.example.com" dig.out.test$n > /dev/null || ret=1
grep "a.example.com.*A.*10.53.0.1" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that in-zone CNAME records returns target data (rd=1/ra=0) ($n)"
ret=0
$DIG $DIGOPTS +rec -p 5300 @10.53.0.1 inzone.example.com > dig.out.test$n || ret=1
grep "ANSWER: 2," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa rd;" dig.out.test$n > /dev/null || ret=1
grep "inzone.example.com.*CNAME.*a.example.com" dig.out.test$n > /dev/null || ret=1
grep "a.example.com.*A.*10.53.0.1" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that in-zone CNAME records returns target data (rd=0/ra=1) ($n)"
ret=0
$DIG $DIGOPTS +norec -p 5300 @10.53.0.2 inzone.example.com > dig.out.test$n || ret=1
grep "ANSWER: 2," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa ra;" dig.out.test$n > /dev/null || ret=1
grep "inzone.example.com.*CNAME.*a.example.com" dig.out.test$n > /dev/null || ret=1
grep "a.example.com.*A.*10.53.0.1" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:check that in-zone CNAME records returns target data (rd=1/ra=1) ($n)"
ret=0
$DIG $DIGOPTS -p 5300 @10.53.0.2 inzone.example.com > dig.out.test$n || ret=1
grep "ANSWER: 2," dig.out.test$n > /dev/null || ret=1
grep "flags: qr aa rd ra;" dig.out.test$n > /dev/null || ret=1
grep "inzone.example.com.*CNAME.*a.example.com" dig.out.test$n > /dev/null || ret=1
grep "a.example.com.*A.*10.53.0.1" dig.out.test$n > /dev/null || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
