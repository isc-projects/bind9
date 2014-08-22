#!/bin/sh
#
# Copyright (C) 2011, 2012  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.4 2011/06/10 01:32:37 each Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

RNDCCMD="$RNDC -s 10.53.0.2 -p 9953 -c ../common/rndc.conf"

status=0

echo "I:test using primary key"
ret=0
$RNDCCMD status > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:test using second key"
ret=0
$RNDC -s 10.53.0.2 -p 9953 -c ns2/secondkey.conf status > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:test 'rndc dumpdb' on a empty cache"
ret=0
$RNDC -s 10.53.0.3 -p 9953 -c ../common/rndc.conf dumpdb > /dev/null || ret=1
for i in 1 2 3 4 5  6 7 8 9
do
	tmp=0
	grep "Dump complete" ns3/named_dump.db > /dev/null || tmp=1
	[ $tmp -eq 0 ] && break
	sleep 1
done
[ $tmp -eq 1 ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:testing rndc with null command"
ret=0
$RNDC -s 10.53.0.3 -p 9953 -c ../common/rndc.conf null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:testing rndc with unknown control channel command"
ret=0
$RNDC -s 10.53.0.3 -p 9953 -c ../common/rndc.conf obviouslynotacommand >/dev/null 2>&1 && ret=1
# rndc: 'obviouslynotacommand' failed: unknown command
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:testing rndc with querylog command"
ret=0
# first enable it with querylog on option
$RNDC -s 10.53.0.3 -p 9953 -c ../common/rndc.conf querylog on >/dev/null 2>&1 || ret=1
# query for builtin and check if query was logged
$DIG @10.53.0.3 -p 5300 -c ch -t txt foo12345.bind > /dev/null || ret 1
grep "query logging is now on" ns3/named.run > /dev/null || ret=1
grep "query: foo12345.bind CH TXT" ns3/named.run > /dev/null || ret=1
# toggle query logging and check again
$RNDC -s 10.53.0.3 -p 9953 -c ../common/rndc.conf querylog >/dev/null 2>&1 || ret=1
# query for another builtin zone and check if query was logged
$DIG @10.53.0.3 -p 5300 -c ch -t txt foo9876.bind > /dev/null || ret 1
grep "query logging is now off" ns3/named.run > /dev/null || ret=1
grep "query: foo9876.bind CH TXT" ns3/named.run > /dev/null && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
