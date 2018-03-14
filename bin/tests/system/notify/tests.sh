#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) Internet Software Consortium.
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

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

#
# Wait up to 10 seconds for the servers to finish starting before testing.
#
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG +tcp -p ${PORT} example @10.53.0.2 soa > dig.out.ns2.test$n || ret=1
	grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
	grep "flags:.* aa[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
	$DIG +tcp -p ${PORT} example @10.53.0.3 soa > dig.out.ns3.test$n || ret=1
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "flags:.* aa[ ;]" dig.out.ns3.test$n > /dev/null || ret=1
	[ $ret = 0 ] && break
	sleep 1
done

n=`expr $n + 1`
echo_i "checking initial status ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "10.0.0.1" dig.out.ns2.test$n > /dev/null || ret=1

$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
grep "10.0.0.1" dig.out.ns3.test$n > /dev/null || ret=1

digcomp dig.out.ns2.test$n dig.out.ns3.test$n || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

nextpart ns3/named.run > /dev/null

sleep 1 # make sure filesystem time stamp is newer for reload.
rm -f ns2/example.db
cp -f ns2/example2.db ns2/example.db

echo_i "reloading with example2 using HUP and waiting up to 45 seconds"
$KILL -HUP `cat ns2/named.pid`

try=0
while test $try -lt 45
do
    nextpart ns3/named.run > tmp
    grep "transfer of 'example/IN' from 10.53.0.2#.*success" tmp > /dev/null && break
    sleep 1
    try=`expr $try + 1`
done

n=`expr $n + 1`
echo_i "checking example2 loaded ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "10.0.0.2" dig.out.ns2.test$n > /dev/null || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

n=`expr $n + 1`
echo_i "checking example2 contents have been transferred after HUP reload ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "10.0.0.2" dig.out.ns2.test$n > /dev/null || ret=1

$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
grep "10.0.0.2" dig.out.ns3.test$n > /dev/null || ret=1

digcomp dig.out.ns2.test$n dig.out.ns3.test$n || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

echo_i "stopping master and restarting with example4 then waiting up to 45 seconds"
$PERL $SYSTEMTESTTOP/stop.pl . ns2

rm -f ns2/example.db
cp -f ns2/example4.db ns2/example.db

$PERL $SYSTEMTESTTOP/start.pl --noclean --restart --port ${PORT} . ns2

try=0
while test $try -lt 45
do
    nextpart ns3/named.run > tmp
    grep "transfer of 'example/IN' from 10.53.0.2#.*success" tmp > /dev/null && break
    sleep 1
    try=`expr $try + 1`
done

n=`expr $n + 1`
echo_i "checking example4 loaded ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "10.0.0.4" dig.out.ns2.test$n > /dev/null || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

n=`expr $n + 1`
echo_i "checking example4 contents have been transfered after restart ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "10.0.0.4" dig.out.ns2.test$n > /dev/null || ret=1

$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
grep "10.0.0.4" dig.out.ns3.test$n > /dev/null || ret=1

digcomp dig.out.ns2.test$n dig.out.ns3.test$n || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

n=`expr $n + 1`
echo_i "checking notify to alternate port with master inheritance ($n)"
$NSUPDATE << EOF
server 10.53.0.2 ${PORT}
zone x21
update add added.x21 0 in txt "test string"
send
EOF
for i in 1 2 3 4 5 6 7 8 9
do
	$DIG $DIGOPTS added.x21. @10.53.0.4 txt -p $EXTRAPORT1 > dig.out.ns4.test$n || ret=1
	grep "test string" dig.out.ns4.test$n > /dev/null && break
	sleep 1
done
grep "test string" dig.out.ns4.test$n > /dev/null || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

n=`expr $n + 1`
echo_i "checking notify to multiple views using tsig ($n)"
ret=0
$NSUPDATE << EOF
server 10.53.0.5 ${PORT}
zone x21
key a aaaaaaaaaaaaaaaaaaaa
update add added.x21 0 in txt "test string"
send
EOF

for i in 1 2 3 4 5 6 7 8 9
do
	$DIG $DIGOPTS added.x21. -y b:bbbbbbbbbbbbbbbbbbbb @10.53.0.5 \
		txt > dig.out.b.ns5.test$n || ret=1
	$DIG $DIGOPTS added.x21. -y c:cccccccccccccccccccc @10.53.0.5 \
		txt > dig.out.c.ns5.test$n || ret=1
	grep "test string" dig.out.b.ns5.test$n > /dev/null &&
	grep "test string" dig.out.c.ns5.test$n > /dev/null &&
        break
	sleep 1
done
grep "test string" dig.out.b.ns5.test$n > /dev/null || ret=1
grep "test string" dig.out.c.ns5.test$n > /dev/null || ret=1

[ $ret = 0 ] || echo_i "failed"
status=`expr $ret + $status`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
