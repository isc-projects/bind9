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
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

n=`expr $n + 1`
echo_i "Checking that reconfiguring empty zones is silent ($n)"
$RNDCCMD 10.53.0.1 reconfig
ret=0
grep "automatic empty zone" ns1/named.run > /dev/null || ret=1
grep "received control channel command 'reconfig'" ns1/named.run > /dev/null || ret=1
grep "reloading configuration succeeded" ns1/named.run > /dev/null || ret=1
sleep 1
grep "zone serial (0) unchanged." ns1/named.run > /dev/null && ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
echo_i "Checking that reloading empty zones is silent ($n)"
$RNDCCMD 10.53.0.1 reload > /dev/null
ret=0
grep "automatic empty zone" ns1/named.run > /dev/null || ret=1
grep "received control channel command 'reload'" ns1/named.run > /dev/null || ret=1
grep "reloading configuration succeeded" ns1/named.run > /dev/null || ret=1
sleep 1
grep "zone serial (0) unchanged." ns1/named.run > /dev/null && ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

VERSION=`../../../../isc-config.sh  --version | cut -d = -f 2`
HOSTNAME=`$FEATURETEST --gethostname`

n=`expr $n + 1`
ret=0
echo_i "Checking that default version works for rndc ($n)"
$RNDCCMD 10.53.0.1 status > rndc.status.ns1.$n 2>&1
grep "^version: BIND $VERSION " rndc.status.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that custom version works for rndc ($n)"
$RNDCCMD 10.53.0.3 status > rndc.status.ns3.$n 2>&1
grep "^version: BIND $VERSION ${DESCRIPTION}${DESCRIPTION:+ }<id:........*> (this is a test of version)" rndc.status.ns3.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that default version works for query ($n)"
$DIG $DIGOPTS +short version.bind txt ch @10.53.0.1 > dig.out.ns1.$n
grep "^\"$VERSION\"$" dig.out.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that custom version works for query ($n)"
$DIG $DIGOPTS +short version.bind txt ch @10.53.0.3 > dig.out.ns3.$n
grep "^\"this is a test of version\"$" dig.out.ns3.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that default hostname works for query ($n)"
$DIG $DIGOPTS +short hostname.bind txt ch @10.53.0.1 > dig.out.ns1.$n
grep "^\"$HOSTNAME\"$" dig.out.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that custom hostname works for query ($n)"
$DIG $DIGOPTS +short hostname.bind txt ch @10.53.0.3 > dig.out.ns3.$n
grep "^\"this.is.a.test.of.hostname\"$" dig.out.ns3.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that default server-id is none for query ($n)"
$DIG $DIGOPTS id.server txt ch @10.53.0.1 > dig.out.ns1.$n
grep "status: NOERROR" dig.out.ns1.$n > /dev/null || ret=1
grep "ANSWER: 0" dig.out.ns1.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that server-id hostname works for query ($n)"
$DIG $DIGOPTS +short id.server txt ch @10.53.0.2 > dig.out.ns2.$n
grep "^\"$HOSTNAME\"$" dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that server-id hostname works for EDNS name server ID request ($n)"
$DIG $DIGOPTS +norec +nsid foo @10.53.0.2 > dig.out.ns2.$n
grep "^; NSID: .* (\"$HOSTNAME\")$" dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that custom server-id works for query ($n)"
$DIG $DIGOPTS +short id.server txt ch @10.53.0.3 > dig.out.ns3.$n
grep "^\"this.is.a.test.of.server-id\"$" dig.out.ns3.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

n=`expr $n + 1`
ret=0
echo_i "Checking that custom server-id works for EDNS name server ID request ($n)"
$DIG $DIGOPTS +norec +nsid foo @10.53.0.3 > dig.out.ns3.$n
grep "^; NSID: .* (\"this.is.a.test.of.server-id\")$" dig.out.ns3.$n > /dev/null || ret=1
if [ $ret != 0 ] ; then echo_i "failed; status=`expr $status + $ret`"; fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
