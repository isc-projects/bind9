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

DIGOPTS="-p ${PORT} +dnssec +time=1 +tries=1 +multi"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

# Wait until the transfer of the given zone to ns3 either completes successfully
# or is aborted by a verification failure.
wait_for_transfer() {
	zone=$1
	for i in 1 2 3 4 5 6 7 8 9 10; do
		nextpartpeek ns3/named.run | egrep "'$zone/IN'.*Transfer status: (success|verify failure)" > /dev/null && return
		sleep 1
	done
	echo_i "exceeded time limit waiting for proof of '$zone' being transferred to appear in ns3/named.run"
	ret=1
}

# Wait until loading the given zone on the given server either completes
# successfully for the specified serial number or fails.
wait_for_load() {
	zone=$1
	serial=$2
	log=$3
	for i in 1 2 3 4 5 6 7 8 9 10; do
		nextpartpeek $log | egrep "$zone.*(loaded serial $serial|unable to load)" > /dev/null && return
		sleep 1
	done
	echo_i "exceeded time limit waiting for proof of '$zone' being loaded to appear in $log"
	ret=1
}

# Trigger a reload of ns2 and wait until loading the given zone completes.
reload_zone() {
	zone=$1
	serial=$2
	$RNDCCMD 10.53.0.2 reload > /dev/null 2>&1
	wait_for_load $zone $serial ns2/named.run
}

status=0
n=0

ORIGINAL_SERIAL=`awk '$2 == "SOA" {print $5}' ns2/verify.db.in`
UPDATED_SERIAL_BAD=`expr ${ORIGINAL_SERIAL} + 1`
UPDATED_SERIAL_GOOD=`expr ${ORIGINAL_SERIAL} + 2`

n=`expr $n + 1`
echo_i "checking that an unsigned mirror zone is rejected ($n)"
ret=0
wait_for_transfer verify-unsigned
$DIG $DIGOPTS @10.53.0.3 +norec verify-unsigned SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_BAD}.*; serial" dig.out.ns3.test$n > /dev/null && ret=1
nextpart ns3/named.run | grep "verify-unsigned.*Zone contains no DNSSEC keys" > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a mirror zone signed using an untrusted key is rejected ($n)"
ret=0
nextpartreset ns3/named.run
wait_for_transfer verify-untrusted
$DIG $DIGOPTS @10.53.0.3 +norec verify-untrusted SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_BAD}.*; serial" dig.out.ns3.test$n > /dev/null && ret=1
nextpart ns3/named.run | grep "verify-untrusted.*No trusted KSK DNSKEY found" > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that an AXFR of an incorrectly signed mirror zone is rejected ($n)"
ret=0
nextpartreset ns3/named.run
wait_for_transfer verify-axfr
$DIG $DIGOPTS @10.53.0.3 +norec verify-axfr SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_BAD}.*; serial" dig.out.ns3.test$n > /dev/null && ret=1
nextpart ns3/named.run | grep "No correct RSASHA256 signature for verify-axfr SOA" > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that an AXFR of an updated, correctly signed mirror zone is accepted ($n)"
ret=0
nextpart ns3/named.run > /dev/null
cat ns2/verify-axfr.db.good.signed > ns2/verify-axfr.db.signed
reload_zone verify-axfr ${UPDATED_SERIAL_GOOD}
$RNDCCMD 10.53.0.3 retransfer verify-axfr > /dev/null 2>&1
wait_for_transfer verify-axfr
$DIG $DIGOPTS @10.53.0.3 +norec verify-axfr SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_GOOD}.*; serial" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
