#!/bin/sh
#
# Copyright (C) 2011  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.3 2011/10/12 00:10:19 marka Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +dnssec"
RANDFILE=random.data

status=0
n=0

n=`expr $n + 1`
echo "I:checking that the zone is signed on initial transfer ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 bits TYPE65534 > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 3," dig.out.ns3.test$n > /dev/null || ret=1
	records=`grep "TYPE65534.*05[0-9A-F][0-9A-F][0-9A-F][0-9A-F]0001" dig.out.ns3.test$n | wc -l`
	[ $records = 2 ] || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone bits
server 10.53.0.2 5300
update add added.bits 0 A 1.2.3.4
send
EOF

n=`expr $n + 1`
echo "I:checking that the record is added on the hidden master ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -p 5300 added.bits A > dig.out.ns2.test$n
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that update has been transfered and has been signed ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 added.bits A > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone bits
server 10.53.0.2 5300
update add bits 0 SOA ns2.bits. . 2011072400 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072400) serial on hidden master ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -p 5300 bits SOA > dig.out.ns2.test$n
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2011072400" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072400) serial in signed zone ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 bits SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072400" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I:checking that the zone is signed on initial transfer, noixfr ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 1 2 3 4 5 6 7 8 9 10 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 noixfr TYPE65534 > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 3," dig.out.ns3.test$n > /dev/null || ret=1
	records=`grep "TYPE65534.*05[0-9A-F][0-9A-F][0-9A-F][0-9A-F]0001" dig.out.ns3.test$n | wc -l`
	[ $records = 2 ] || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone noixfr
server 10.53.0.4 5300
update add added.noixfr 0 A 1.2.3.4
send
EOF

n=`expr $n + 1`
echo "I:checking that the record is added on the hidden master, noixfr ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.4 -p 5300 added.noixfr A > dig.out.ns4.test$n
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that update has been transfered and has been signed, noixfr ($n)"
ret=0
for i in 1 2 3 4 5 6 7 8 9 10 1 2 3 4 5 6 7 8 9 10 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 added.noixfr A > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone noixfr
server 10.53.0.4 5300
update add noixfr 0 SOA ns4.noixfr. . 2011072400 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072400) serial on hidden master, noixfr ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.4 -p 5300 noixfr SOA > dig.out.ns4.test$n
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns4.test$n > /dev/null || ret=1
grep "2011072400" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072400) serial in signed zone, noixfr ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 noixfr SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072400" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:stop bump in the wire signer server ($n)"
ret=0
$PERL ../stop.pl . ns3 || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:restart bump in the wire signer server ($n)"
ret=0
$PERL ../start.pl --noclean . ns3 || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone bits
server 10.53.0.2 5300
update add bits 0 SOA ns2.bits. . 2011072450 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072450) serial on hidden master ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -p 5300 bits SOA > dig.out.ns2.test$n
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2011072450" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072450) serial in signed zone ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 bits SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072450" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone noixfr
server 10.53.0.4 5300
update add noixfr 0 SOA ns4.noixfr. . 2011072450 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072450) serial on hidden master, noixfr ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.4 -p 5300 noixfr SOA > dig.out.ns4.test$n
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns4.test$n > /dev/null || ret=1
grep "2011072450" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking YYYYMMDDVV (2011072450) serial in signed zone, noixfr ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 noixfr SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072450" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone bits
server 10.53.0.3 5300
update add bits 0 SOA ns2.bits. . 2011072460 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking forwarded update on hidden master ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 -p 5300 bits SOA > dig.out.ns2.test$n
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns2.test$n > /dev/null || ret=1
grep "2011072460" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking forwarded update on signed zone ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 bits SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072460" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

$NSUPDATE << EOF
zone noixfr
server 10.53.0.3 5300
update add noixfr 0 SOA ns4.noixfr. . 2011072460 20 20 1814400 3600
send
EOF

n=`expr $n + 1`
echo "I:checking forwarded update on hidden master, noixfr ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.4 -p 5300 noixfr SOA > dig.out.ns4.test$n
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns4.test$n > /dev/null || ret=1
grep "2011072460" dig.out.ns4.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking forwarded update on signed zone, noixfr ($n)"
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.3 -p 5300 noixfr SOA > dig.out.ns3.test$n
	grep "status: NOERROR" dig.out.ns3.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns3.test$n > /dev/null || ret=1
	grep "2011072460" dig.out.ns3.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking turning on of inline signing in a slave zone via reload ($n)"
$DIG $DIGOPTS @10.53.0.5 -p 5300 +dnssec bits SOA > dig.out.ns5.test$n
grep "status: NOERROR" dig.out.ns5.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.ns5.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:setup broken"; fi
status=`expr $status + $ret`
cp ns5/named.conf.post ns5/named.conf
(cd ns5; $KEYGEN -q -r ../$RANDFILE bits) > /dev/null 2>&1
(cd ns5; $KEYGEN -q -r ../$RANDFILE -f KSK bits) > /dev/null 2>&1
$RNDC -c ../common/rndc.conf -s 10.53.0.5 -p 9953 reload 2>&1 | sed 's/^/I:ns5 /'
for i in 1 2 3 4 5 6 7 8 9 10
do
	ret=0
	$DIG $DIGOPTS @10.53.0.5 -p 5300 bits SOA > dig.out.ns5.test$n
	grep "status: NOERROR" dig.out.ns5.test$n > /dev/null || ret=1
	grep "ANSWER: 2," dig.out.ns5.test$n > /dev/null || ret=1
	if [ $ret = 0 ]; then break; fi
	sleep 1
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

exit $status
