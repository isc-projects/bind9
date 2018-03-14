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

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +nocmd +dnssec -p ${PORT}"
ANSWEROPTS="+noall +answer +dnssec -p ${PORT}"
DELVOPTS="-a ns1/trusted.conf -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

newtest() {
	n=`expr $n + 1`
	echo_i "$@ ($n)"
	ret=0
}

newtest "get test ids ($n)"
$DIG $DIGOPTS . dnskey +short +rrcomm @10.53.0.1 > dig.out.ns1.test$n || ret=1
oldid=`sed -n 's/.*key id = //p' < dig.out.ns1.test$n`
oldid=`expr "0000${oldid}" : '.*\(.....\)$'`
newid=`expr ${oldid} + 1000 % 65536`
newid=`expr "0000${newid}" : '.*\(.....\)$'`
badid=`expr ${oldid} + 7777 % 65536`
badid=`expr "0000${badid}" : '.*\(.....\)$'`
echo_i "test ids: oldid=${oldid} newid=${newid} badid=${badid}"
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check authoritative server"
$DIG $DIGOPTS @10.53.0.3 example SOA > dig.out.ns3.test$n
grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check test zone resolves with 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 example SOA > dig.out.ns3.test$n
grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-is-ta with old ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-is-ta-${oldid}.example A > dig.out.ns3.test$n || ret=1
grep "status: SERVFAIL" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with old ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-not-ta-${oldid}.example A > dig.out.ns3.test$n || ret=1
grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-is-ta with new ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-is-ta-${newid}.example A > dig.out.ns3.test$n || ret=1
grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with new ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-not-ta-${newid}.example A > dig.out.ns3.test$n || ret=1
grep "status: SERVFAIL" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi

newtest "check kskroll-sentinel-is-ta with bad ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-is-ta-${badid}.example A > dig.out.ns3.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with bad ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.3 kskroll-sentinel-not-ta-${bad}.example A > dig.out.ns3.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi

newtest "check test zone resolves with 'kskroll-sentinel-enable no;'"
$DIG $DIGOPTS @10.53.0.4 example SOA > dig.out.ns4.test$n
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-is-ta with old ta and 'kskroll-sentinel-enable no;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-is-ta-${oldid}.example A > dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with old ta and 'kskroll-sentinel-enable no;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-not-ta-${oldid}.example A > dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-is-ta with new ta and 'kskroll-sentinel-enable no;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-is-ta-${newid}.example A > dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with new ta and 'kskroll-sentinel-enable no;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-not-ta-${newid}.example A > dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi

newtest "check kskroll-sentinel-is-ta with bad ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-is-ta-${badid}.example A > dig.out.ns4.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

newtest "check kskroll-sentinel-not-ta with bad ta and 'kskroll-sentinel-enable yes;'"
$DIG $DIGOPTS @10.53.0.4 kskroll-sentinel-not-ta-${bad}.example A > dig.out.ns4.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
