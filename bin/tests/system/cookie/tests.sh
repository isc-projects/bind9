#!/bin/sh
#
# Copyright (C) 2014-2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

getcookie() {
	awk '$2 == "COOKIE:" {
		print $3;
	}' < $1
}

fullcookie() {
	awk 'BEGIN { n = 0 }
	     // { v[n++] = length(); }
	     END { print (v[1] == v[2]); }'
}

havetc() {
	grep 'flags:.* tc[^;]*;' $1 > /dev/null
}

for bad in bad*.conf
do
	n=`expr $n + 1`
        echo_i "checking that named-checkconf detects error in $bad ($n)"
        ret=0
        $CHECKCONF $bad > /dev/null 2>&1 && ret=1
        if [ $ret != 0 ]; then echo_i "failed"; fi
        status=`expr $status + $ret`
done

for good in good*.conf
do
	n=`expr $n + 1`
        echo_i "checking that named-checkconf detects accepts $good ($n)"
        ret=0
        $CHECKCONF $good > /dev/null 2>&1 || ret=1
        if [ $ret != 0 ]; then echo_i "failed"; fi
        status=`expr $status + $ret`
done

n=`expr $n + 1`
echo_i "checking COOKIE token returned to empty COOKIE option ($n)"
ret=0
$DIG $DIGOPTS +qr +cookie version.bind txt ch @10.53.0.1 > dig.out.test$n
grep COOKIE: dig.out.test$n > /dev/null || ret=1
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking response size without COOKIE ($n)"
ret=0
$DIG $DIGOPTS large.example txt @10.53.0.1 +ignore > dig.out.test$n
havetc dig.out.test$n || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking response size without valid COOKIE ($n)"
ret=0
$DIG $DIGOPTS +cookie large.example txt @10.53.0.1 +ignore > dig.out.test$n
havetc dig.out.test$n || ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking response size with COOKIE ($n)"
ret=0
$DIG $DIGOPTS +cookie large.example txt @10.53.0.1 > dig.out.test$n.l
cookie=`getcookie dig.out.test$n.l`
$DIG $DIGOPTS +qr +cookie=$cookie large.example txt @10.53.0.1 +ignore > dig.out.test$n
havetc dig.out.test$n && ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking response size with COOKIE recursive ($n)"
ret=0
$DIG $DIGOPTS +qr +cookie=$cookie large.xxx txt @10.53.0.1 +ignore > dig.out.test$n
havetc dig.out.test$n && ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking COOKIE is learnt for TCP retry ($n)"
ret=0
$DIG $DIGOPTS +qr +cookie large.example txt @10.53.0.1 > dig.out.test$n
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 3 ]; then ret=1; fi
checkfull=`getcookie dig.out.test$n | fullcookie`
if [ $checkfull != 1 ]; then ret=1; fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking for COOKIE value in adb ($n)"
ret=0
$RNDCCMD 10.53.0.1 dumpdb
sleep 1
grep "10.53.0.2.*\[cookie=" ns1/named_dump.db > /dev/null|| ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking require-server-cookie default (no) ($n)"
ret=0
$DIG $DIGOPTS +qr +cookie +nobadcookie soa @10.53.0.1 > dig.out.test$n
grep BADCOOKIE dig.out.test$n > /dev/null && ret=1
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 2 ]; then ret=1; fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking require-server-cookie yes ($n)"
ret=0
$DIG $DIGOPTS +qr +cookie +nobadcookie soa @10.53.0.3 > dig.out.test$n
grep "flags: qr[^;]* aa[ ;]" dig.out.test$n > /dev/null && ret=1
grep "flags: qr[^;]* ad[ ;]" dig.out.test$n > /dev/null && ret=1
grep BADCOOKIE dig.out.test$n > /dev/null || ret=1
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 2 ]; then ret=1; fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`


echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
