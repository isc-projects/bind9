#!/bin/sh
#
# Copyright (C) 2012, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.1.4.11 2012/02/01 16:54:32 each Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd"
DIGCMD="$DIG $DIGOPTS -p 5300"
RNDCCMD="$RNDC -p 9953 -c ../common/rndc.conf"

status=0

ret=0
n=1

echo "I:fetching a.example from ns2's initial configuration ($n)"
$DIGCMD +noauth a.example. @10.53.0.2 any > dig.out.ns2.1 || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:verifying adb records in named.stats ($n)"
$RNDCCMD -s 10.53.0.2 stats > /dev/null 2>&1
echo "I: checking for 1 entry in adb hash table in named.stats"
grep "1 Addresses in hash table" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I: verifying cache statistics in named.stats ($n)"
grep "Cache Statistics" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I: checking for 2 entries in adb hash table in named.stats"
$DIGCMD a.example.info. @10.53.0.2 any > /dev/null 2>&1

ret=0
$RNDCCMD -s 10.53.0.2 stats > /dev/null 2>&1
grep "2 Addresses in hash table" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:dumping initial stats for ns3"
rm -f ns3/named.stats
$RNDCCMD -s 10.53.0.3 stats > /dev/null 2>&1
[ -f ns3/named.stats ] || ret=1
nsock0nstat=`grep "UDP/IPv4 sockets active" ns3/named.stats | awk '{print $1}'`

echo "I:sending queries to ns3"
$DIGCMD +tries=2 +time=1 +recurse @10.53.0.3 foo.info. any > /dev/null 2>&1
#$DIGCMD +tries=2 +time=1 +recurse @10.53.0.3 foo.info. any
echo "I:dumping updated stats for ns3 ($n)"
rm -f ns3/named.stats
$RNDCCMD -s 10.53.0.3 stats > /dev/null 2>&1
[ -f ns3/named.stats ] || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I: verifying recursing clients output in named.stats ($n)"
grep "2 recursing clients" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I: verifying active fetches output in named.stats ($n)"
grep "1 active fetches" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I: verifying active sockets output in named.stats"
nsock1nstat=`grep "UDP/IPv4 sockets active" ns3/named.stats | awk '{print $1}'`

ret=0
[ `expr $nsock1nstat - $nsock0nstat` -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
# there should be 1 UDP and no TCP queries.  As the TCP counter is zero
# no status line is emitted.
echo "I: verifying queries in progress in named.stats ($n)"
grep "1 UDP queries in progress" ns3/named.stats > /dev/null || ret=1
grep "TCP queries in progress" ns3/named.stats > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I: verifying bucket size output ($n)"
grep "bucket size" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
n=`expr $n + 1`
echo "I:checking that zones with slash are properly shown in XML output ($n)"
if ./xmlstats && [ -x ${CURL} ] ; then
    ${CURL} http://10.53.0.1:8053/xml/v3/zones > curl.out.${t} 2>/dev/null || ret=1
    grep '<zone name="32/1.0.0.127-in-addr.example" rdataclass="IN">' curl.out.${t} > /dev/null || ret=1
else
    echo "I:skipping test as libxml2 and/or curl was not found"
fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo "I:checking that zones return their type ($n)"
if ./xmlstats && [ -x ${CURL} ] ; then
    ${CURL} http://10.53.0.1:8053/xml/v3/zones > curl.out.${t} 2>/dev/null || ret=1
    grep '<zone name="32/1.0.0.127-in-addr.example" rdataclass="IN"><type>master</type>' curl.out.${t} > /dev/null || ret=1
else
    echo "I:skipping test as libxml2 and/or curl was not found"
fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
