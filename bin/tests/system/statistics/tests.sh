#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd"
DIGCMD="$DIG $DIGOPTS -p ${PORT}"
RNDCCMD="$RNDC -p ${CONTROLPORT} -c ../common/rndc.conf"

status=0

ret=0
n=1

echo_i "fetching a.example from ns2's initial configuration ($n)"
$DIGCMD +noauth a.example. @10.53.0.2 any > dig.out.ns2.1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "dumping initial stats for ns2 ($n)"
$RNDCCMD -s 10.53.0.2 stats > /dev/null 2>&1
[ -f ns2/named.stats ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "verifying adb records in named.stats ($n)"
grep "ADB stats" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "checking for 1 entry in adb hash table in named.stats ($n)"
grep "1 Addresses in hash table" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "verifying cache statistics in named.stats ($n)"
grep "Cache Statistics" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "checking for 2 entries in adb hash table in named.stats ($n)"
$DIGCMD a.example.info. @10.53.0.2 any > /dev/null 2>&1
$RNDCCMD -s 10.53.0.2 stats > /dev/null 2>&1
grep "2 Addresses in hash table" ns2/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "dumping initial stats for ns3 ($n)"
rm -f ns3/named.stats
$RNDCCMD -s 10.53.0.3 stats > /dev/null 2>&1
[ -f ns3/named.stats ] || ret=1
[ "$CYGWIN" ] || \
nsock0nstat=`grep "UDP/IPv4 sockets active" ns3/named.stats | awk '{print $1}'`
[ 0 -ne ${nsock0nstat:-0} ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "sending queries to ns3"
$DIGCMD +tries=2 +time=1 +recurse @10.53.0.3 foo.info. any > /dev/null 2>&1

ret=0
echo_i "dumping updated stats for ns3 ($n)"
rm -f ns3/named.stats
$RNDCCMD -s 10.53.0.3 stats > /dev/null 2>&1
[ -f ns3/named.stats ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "verifying recursing clients output in named.stats ($n)"
grep "2 recursing clients" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "verifying active fetches output in named.stats ($n)"
grep "1 active fetches" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

if [ ! "$CYGWIN" ]; then
    ret=0
    echo_i "verifying active sockets output in named.stats ($n)"
    nsock1nstat=`grep "UDP/IPv4 sockets active" ns3/named.stats | awk '{print $1}'`
    [ `expr $nsock1nstat - $nsock0nstat` -eq 1 ] || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
    n=`expr $n + 1`
fi

# there should be 1 UDP and no TCP queries.  As the TCP counter is zero
# no status line is emitted.
ret=0
echo_i "verifying queries in progress in named.stats ($n)"
grep "1 UDP queries in progress" ns3/named.stats > /dev/null || ret=1
grep "TCP queries in progress" ns3/named.stats > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "verifying bucket size output ($n)"
grep "bucket size" ns3/named.stats > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo_i "checking that zones with slash are properly shown in XML output ($n)"
if $FEATURETEST --have-libxml2 && [ -x ${CURL} ] ; then
    ${CURL} http://10.53.0.1:${EXTRAPORT1}/xml/v3/zones > curl.out.${t} 2>/dev/null || ret=1
    grep '<zone name="32/1.0.0.127-in-addr.example" rdataclass="IN">' curl.out.${t} > /dev/null || ret=1
else
    echo_i "skipping test as libxml2 and/or curl was not found"
fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
