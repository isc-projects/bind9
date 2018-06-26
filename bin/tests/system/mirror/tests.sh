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

RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

# Wait until the transfer of the given zone to ns3 either completes successfully
# or is aborted by a verification failure.
wait_for_transfer() {
	zone=`echo $1 | sed "s/\./\./g;"`
	for i in 1 2 3 4 5 6 7 8 9 10; do
		nextpartpeek ns3/named.run | egrep "'$zone/IN'.*Transfer status: (success|verify failure)" > /dev/null && break
		sleep 1
	done
}

# Wait until loading the given zone on the given server either completes
# successfully for the specified serial number or fails.
wait_for_load() {
	zone=$1
	serial=$2
	log=$3
	for i in 1 2 3 4 5 6 7 8 9 10; do
		nextpartpeek $log | egrep "$zone.*(loaded serial $serial|unable to load)" > /dev/null && break
		sleep 1
	done
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

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
