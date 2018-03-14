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

status=0
n=0

echo_i ">>>> Config: named1.conf"

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server that does not have ECS enabled."
echo_i "Check that it does not return an ECS response when sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server that does not have ECS enabled."
echo_i "Check that it does not return an ECS response when sent an ECS query"
echo_i "with SOURCE = 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0/0 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server that does not have ECS enabled."
echo_i "Check that it does not return an ECS response when sent an ECS query"
echo_i "with SOURCE > 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named2.conf"
cp -f ns1/named2.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, but no"
echo_i "match-ecs-clients{}. Check that it does not return an ECS response when"
echo_i "sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, but no"
echo_i "match-ecs-clients{}. Check that it returns an ECS response when"
echo_i "sent an ECS query with SOURCE = 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0/0 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*0.0.0.0/0/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, but no"
echo_i "match-ecs-clients{}. Check that it returns an ECS response when"
echo_i "sent an ECS query with SOURCE > 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*10.53.0.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns FORMERR"
echo_i "on invalid ECS option #1 (contains only FAMILY)."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:0000 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: FORMERR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns FORMERR"
echo_i "on invalid ECS option #2 (contains FAMILY=3)."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:00030000 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: FORMERR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns FORMERR"
echo_i "on invalid ECS option #3 (contains FAMILY=1,SOURCE=24,SCOPE=24,ADDRESS=1.1.1)."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:00011818010101 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: FORMERR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns FORMERR"
echo_i "on invalid ECS option #4 (contains FAMILY=1,SOURCE=48,SCOPE=0,ADDRESS=0.0.0.0)."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:0001300000000000 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: FORMERR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns FORMERR"
echo_i "on invalid ECS option #5 (contains FAMILY=1,SOURCE=24,SCOPE=0,ADDRESS=1.1.1.1)."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:0001180001010101 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: FORMERR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns NOERROR"
echo_i "on ECS option with FAMILY=0, SOURCE=0, SCOPE=0, ADDRESSPREFIX=empty."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:00000000 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*0/0/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled returns NOERROR"
echo_i "on ECS option with FAMILY=1, SOURCE=24, SCOPE=0, ADDRESSPREFIX=1.1.1."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +ednsopt=8:00011800010101 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*1.1.1.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named3.conf"
cp -f ns1/named3.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with client not in ecs-enable-from{}."
echo_i "Check that it does not return an ECS response when sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with client not in ecs-enable-from{}."
echo_i "Check that it does not return an ECS response when sent an ECS query"
echo_i "with SOURCE = 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0/0 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with client not in ecs-enable-from{}."
echo_i "Check that it does not return an ECS response when sent an ECS query"
echo_i "with SOURCE > 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named4.conf"
cp -f ns1/named4.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and matching"
echo_i "ecs-enable-from{}. Check that it does not return an ECS response when"
echo_i "sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and matching"
echo_i "ecs-enable-from{}. Check that it returns an ECS response when"
echo_i "sent an ECS query with SOURCE = 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0/0 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*0.0.0.0/0/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and matching"
echo_i "ecs-enable-from{}. Check that it returns an ECS response when"
echo_i "sent an ECS query with SOURCE > 0."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*10.53.0.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named5.conf"
cp -f ns1/named5.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and existing but"
echo_i "unmatched match-ecs-clients{192.168.0.0/24;} and no"
echo_i "match-ecs-clients{any;} and match-clients{none;}. It should return"
echo_i "SERVFAIL, just like when a zone is configured but failed loading."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*10.53.0.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: SERVFAIL' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and existing"
echo_i "matched match-ecs-clients{192.168.0.0/24;} and no"
echo_i "match-ecs-clients{any;} and match-clients{none;}. It should return"
echo_i "a successful answer from the matched view."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=192.168.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*192.168.0.0/24/24' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named6.conf"
cp -f ns1/named6.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and global"
echo_i "match-ecs-clients{any;}. It should return SCOPE=0 for any prefix."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*10.53.0.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=192.168.0.0/24 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET.*192.168.0.0/24/0' dig.out.ns1.${n} > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and global"
echo_i "match-ecs-clients{any;}. It should not return an ECS response"
echo_i "when sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named7.conf"
cp -f ns1/named7.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and global"
echo_i "match-clients{any;}. It should return SCOPE=0 for any prefix."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.0.0/24 > dig.out.ns1.${n}.1 || ret=1
grep 'CLIENT-SUBNET.*10.53.0.0/24/0' dig.out.ns1.${n}.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n}.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=192.168.0.0/24 > dig.out.ns1.${n}.2 || ret=1
grep 'CLIENT-SUBNET.*192.168.0.0/24/0' dig.out.ns1.${n}.2 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n}.2 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and global"
echo_i "match-clients{any;}. It should not return an ECS response"
echo_i "when sent a non-ECS query."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n} || ret=1
grep 'CLIENT-SUBNET' dig.out.ns1.${n} > /dev/null && ret=1
grep 'status: NOERROR' dig.out.ns1.${n} > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed"
status=`expr $status + $ret`

echo_i ">>>> Config: named8.conf"
cp -f ns1/named8.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and multiple /24"
echo_i "match-ecs-clients{} views, that multiple prefixes return different"
echo_i "configured data based on the source address, with correct scope."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n}.nonecs || ret=1
grep "CLIENT-SUBNET" dig.out.ns1.${n}.nonecs > /dev/null && ret=1
grep 'status: REFUSED' dig.out.ns1.${n}.nonecs > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed nonecs"
status=`expr $status + $ret`
for i in 1 2 3 4 5 6 7 8; do
    ret=0
    $DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.$i.1/32 > dig.out.ns1.${n}.$i.1 || ret=1
    grep "CLIENT-SUBNET.*10.53.$i.1/32/24" dig.out.ns1.${n}.$i.1 > /dev/null || ret=1
    grep 'status: NOERROR' dig.out.ns1.${n}.$i.1 > /dev/null || ret=1
    [ $ret -eq 0 ] || echo_i "failed +subnet=10.53.$i.1/32 a"
    status=`expr $status + $ret`

    ret=0
    $DIG +short -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.53.$i.1/32 > dig.out.ns1.${n}.$i.2 || ret=1
    j=`cat dig.out.ns1.$n.$i.2 | tr -d '"'`
    [ "$i" = "$j" ] || ret=1
    [ $ret -eq 0 ] || echo_i "failed +subnet=10.53.$i.1/32 b"
    status=`expr $status + $ret`
done

echo_i ">>>> Config: named9.conf"
cp -f ns1/named9.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and multiple /16"
echo_i "match-ecs-clients{} views, that multiple prefixes return different"
echo_i "configured data based on the source address, with correct scope."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n}.nonecs || ret=1
grep "CLIENT-SUBNET" dig.out.ns1.${n}.nonecs > /dev/null && ret=1
grep 'status: REFUSED' dig.out.ns1.${n}.nonecs > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed nonecs"
status=`expr $status + $ret`
for i in 1 2 3 4 5 6 7 8; do
    ret=0
    $DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.$i.0.0/24 > dig.out.ns1.${n}.$i.1 || ret=1
    grep "CLIENT-SUBNET.*10.$i.0.0/24/16" dig.out.ns1.${n}.$i.1 > /dev/null || ret=1
    grep 'status: NOERROR' dig.out.ns1.${n}.$i.1 > /dev/null || ret=1
    [ $ret -eq 0 ] || echo_i "failed +subnet=10.$i.0.0/24 a"
    status=`expr $status + $ret`

    ret=0
    $DIG +short -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=10.$i.0.0/24 > dig.out.ns1.${n}.$i.2 || ret=1
    j=`cat dig.out.ns1.$n.$i.2 | tr -d '"'`
    [ "$i" = "$j" ] || ret=1
    [ $ret -eq 0 ] || echo_i "failed +subnet=10.$i.0.0/24 b"
    status=`expr $status + $ret`
done

echo_i ">>>> Config: named10.conf"
cp -f ns1/named10.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/I:ns1 /'
echo_i ">>>> sleeping 2 seconds"
sleep 2

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and multiple"
echo_i "match-ecs-clients{} views including a match-ecs-clients{any;};,"
echo_i "that a query that matches match-ecs-clients{any;}; is returned"
echo_i "a reply with SCOPE=32."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 > dig.out.ns1.${n}.nonecs || ret=1
grep "CLIENT-SUBNET" dig.out.ns1.${n}.nonecs > /dev/null && ret=1
grep 'status: REFUSED' dig.out.ns1.${n}.nonecs > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed nonecs"
status=`expr $status + $ret`
ret=0
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=192.168.1.0/24 > dig.out.ns1.${n}.1 || ret=1
grep 'CLIENT-SUBNET.*192.168.1.0/24/32' dig.out.ns1.${n}.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n}.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed a"
status=`expr $status + $ret`
ret=0
$DIG +short -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=192.168.1.0/24 > dig.out.ns1.${n}.2 || ret=1
j=`cat dig.out.ns1.$n.2 | tr -d '"'`
[ "1" = "$j" ] || ret=1
[ $ret -eq 0 ] || echo_i "failed b"
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo_i "==== Test: ${n}"
echo_i "Test named as authoritative server with ECS enabled, and multiple"
echo_i "match-ecs-clients{} views including a match-ecs-clients{any;};,"
echo_i "that a query with +subnet=0/0 is returned a reply with SCOPE=32."
echo_i "The SCOPE=32 makes no sense when FAMILY=0, but this would prevent"
echo_i "broken resolvers from caching it as a /0 scope answer."
$DIG -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0 > dig.out.ns1.${n}.1 || ret=1
grep 'CLIENT-SUBNET.*0.0.0.0/0/32' dig.out.ns1.${n}.1 > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns1.${n}.1 > /dev/null || ret=1
[ $ret -eq 0 ] || echo_i "failed a"
status=`expr $status + $ret`
ret=0
$DIG +short -p ${PORT} @10.53.0.1 txt example -b 127.0.0.1 +subnet=0 > dig.out.ns1.${n}.2 || ret=1
j=`cat dig.out.ns1.$n.2 | tr -d '"'`
[ "1" = "$j" ] || ret=1
[ $ret -eq 0 ] || echo_i "failed b"
status=`expr $status + $ret`

# test scope with overlapping prefixes (should return scope=32)
# test client address matching vs. ECS address prefix matching
# test IPv6 queries

# check that with match-clients and match-ecs-clients, and an ECS option in the request, (1) ECS takes precedence, and (2) only if there are _no_ match-ecs-clients{} views, match-clients{any;} only is returned with scope=0, (3) otherwise it SERVFAILs
# check that with match-clients and match-ecs-clients, and no ECS option in the request, only the match-clients{} views are matched

# NOTE: test in all above cases where ECS is configured that no ECS option is returned when there's none in the query
# NOTE: check that the response ECS option is well formed in all cases (check that address prefix and scope match, and source is as expected)
# NOTE: interoperability testing should be done with named as ECS resolver on the subscription branch (in a separate ticket)

echo_i "==== Done"
echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
