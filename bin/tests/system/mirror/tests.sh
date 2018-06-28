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

n=`expr $n + 1`
echo_i "checking that an IXFR of an incorrectly signed mirror zone is rejected ($n)"
nextpartreset ns3/named.run
ret=0
wait_for_transfer verify-ixfr
nextpart ns3/named.run > /dev/null
# Wait 1 second so that the zone file timestamp changes and the subsequent
# invocation of "rndc reload" triggers a zone reload.
sleep 1
cat ns2/verify-ixfr.db.bad.signed > ns2/verify-ixfr.db.signed
reload_zone verify-ixfr ${UPDATED_SERIAL_BAD}
# Trigger IXFR.
$RNDCCMD 10.53.0.3 refresh verify-ixfr > /dev/null 2>&1
wait_for_transfer verify-ixfr
# Ensure the transfer was incremental as expected.
if [ `nextpartpeek ns3/named.run | grep "verify-ixfr.*got incremental response" | wc -l` -eq 0 ]; then
	echo_i "failed: did not get an incremental response"
	ret=1
fi
# Ensure the new, bad version of the zone was not accepted.
$DIG $DIGOPTS @10.53.0.3 +norec verify-ixfr SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_BAD}.*; serial" dig.out.ns3.test$n > /dev/null && ret=1
nextpart ns3/named.run | grep "No correct RSASHA256 signature for verify-ixfr SOA" > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that an IXFR of an updated, correctly signed mirror zone is accepted after AXFR failover ($n)"
ret=0
nextpart ns3/named.run > /dev/null
# Wait 1 second so that the zone file timestamp changes and the subsequent
# invocation of "rndc reload" triggers a zone reload.
sleep 1
cat ns2/verify-ixfr.db.good.signed > ns2/verify-ixfr.db.signed
reload_zone verify-ixfr ${UPDATED_SERIAL_GOOD}
# Trigger IXFR.
$RNDCCMD 10.53.0.3 refresh verify-ixfr > /dev/null 2>&1
wait_for_transfer verify-ixfr
# Ensure the new, good version of the zone was accepted.
$DIG $DIGOPTS @10.53.0.3 +norec verify-ixfr SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_GOOD}.*; serial" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that loading an incorrectly signed mirror zone from disk fails ($n)"
ret=0
nextpartreset ns3/named.run
wait_for_load verify-load ${UPDATED_SERIAL_BAD} ns3/named.run
$DIG $DIGOPTS @10.53.0.3 +norec verify-load SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_BAD}.*; serial" dig.out.ns3.test$n > /dev/null && ret=1
nextpart ns3/named.run | grep "No correct RSASHA256 signature for verify-load SOA" > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that loading a correctly signed mirror zone from disk succeeds ($n)"
ret=0
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc --port ${CONTROLPORT} . ns3
cat ns2/verify-load.db.good.signed > ns3/verify-load.db.mirror
nextpart ns3/named.run > /dev/null
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart --port ${PORT} . ns3
wait_for_load verify-load ${UPDATED_SERIAL_GOOD} ns3/named.run
$DIG $DIGOPTS @10.53.0.3 +norec verify-load SOA > dig.out.ns3.test$n 2>&1 || ret=1
grep "${UPDATED_SERIAL_GOOD}.*; serial" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
