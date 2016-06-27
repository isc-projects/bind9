#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011-2013, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.12 2011/11/02 23:46:24 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

DIGOPTS="-p 5300"

echo "I:querying for various representations of an IN A record"
for i in 1 2 3 4 5 6 7 8 9 10 11 12
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 a$i.example a in > dig.out || ret=1
	echo 10.0.0.1 | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for various representations of an IN TXT record"
for i in 1 2 3 4 5 6 7
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 txt$i.example txt in > dig.out || ret=1
	echo '"hello"' | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for various representations of an IN TYPE123 record"
for i in 1 2 3
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 unk$i.example type123 in > dig.out || ret=1
	echo '\# 1 00' | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for NULL record"
ret=0
$DIG +short $DIGOPTS @10.53.0.1 null.example null in > dig.out || ret=1
echo '\# 1 00' | diff - dig.out || ret=1
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:querying for empty NULL record"
ret=0
$DIG +short $DIGOPTS @10.53.0.1 empty.example null in > dig.out || ret=1
echo '\# 0' | diff - dig.out || ret=1
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:querying for various representations of a CLASS10 TYPE1 record"
for i in 1 2
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 a$i.example a class10 > dig.out || ret=1
	echo '\# 4 0A000001' | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for various representations of a CLASS10 TXT record"
for i in 1 2 3 4
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 txt$i.example txt class10 > dig.out || ret=1
	echo '"hello"' | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for various representations of a CLASS10 TYPE123 record"
for i in 1 2
do
	ret=0
	$DIG +short $DIGOPTS @10.53.0.1 unk$i.example type123 class10 > dig.out || ret=1
	echo '\# 1 00' | diff - dig.out || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:querying for SOAs of zone that should have failed to load"
for i in 1 2 3 4
do
	ret=0
	$DIG $DIGOPTS @10.53.0.1 broken$i. soa in > dig.out || ret=1
	grep "SERVFAIL" dig.out > /dev/null || ret=1
	if [ $ret != 0 ]
	then
		echo "#$i failed"
	fi
	status=`expr $status + $ret`
done

echo "I:checking large unknown record loading on master"
ret=0
$DIG $DIGOPTS @10.53.0.1 +tcp +short large.example TYPE45234 > dig.out || { ret=1 ; echo I: dig failed ; }
diff -s large.out dig.out > /dev/null || { ret=1 ; echo "I: diff failed"; }
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:checking large unknown record loading on slave"
ret=0
$DIG $DIGOPTS @10.53.0.2 +tcp +short large.example TYPE45234 > dig.out || { ret=1 ; echo I: dig failed ; }
diff -s large.out dig.out > /dev/null || { ret=1 ; echo "I: diff failed"; }
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:stop and restart slave"
$PERL $SYSTEMTESTTOP/stop.pl . ns2
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns2

echo "I:checking large unknown record loading on slave"
ret=0
$DIG $DIGOPTS @10.53.0.2 +tcp +short large.example TYPE45234 > dig.out || { ret=1 ; echo I: dig failed ; }
diff -s large.out dig.out > /dev/null || { ret=1 ; echo "I: diff failed"; }
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:checking large unknown record loading on inline slave"
ret=0
$DIG $DIGOPTS @10.53.0.3 +tcp +short large.example TYPE45234 > dig.out || { ret=1 ; echo I: dig failed ; }
diff large.out dig.out > /dev/null || { ret=1 ; echo "I: diff failed"; }
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:stop and restart inline slave"
$PERL $SYSTEMTESTTOP/stop.pl . ns3
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns3

echo "I:checking large unknown record loading on inline slave"
ret=0
$DIG $DIGOPTS @10.53.0.3 +tcp +short large.example TYPE45234 > dig.out || { ret=1 ; echo I: dig failed ; }
diff large.out dig.out > /dev/null || { ret=1 ; echo "I: diff failed"; }
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:check that '"'"\\#"'"' is not treated as the unknown escape sequence"
ret=0
$DIG $DIGOPTS @10.53.0.1 +tcp +short txt8.example txt > dig.out
echo '"#" "2" "0145"' | diff - dig.out || ret=1
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:check that 'TXT \# text' is not treated as the unknown escape sequence"
ret=0
$DIG $DIGOPTS @10.53.0.1 +tcp +short txt9.example txt > dig.out
echo '"#" "text"' | diff - dig.out || ret=1
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`

echo "I:check that 'TYPE353 \# cat' produces 'not a valid number'"
ret=0
$CHECKZONE nan.bad zones/nan.bad > check.out 2>&1
grep "not a valid number" check.out > /dev/null || ret=1
[ $ret = 0 ] || echo "I: failed"
status=`expr $status + $ret`



echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
