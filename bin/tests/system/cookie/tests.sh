#!/bin/sh
#
# Copyright (C) 2014-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.22 2012/02/09 23:47:18 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

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
        echo "I:checking that named-checkconf detects error in $bad ($n)"
        ret=0
        $CHECKCONF $bad > /dev/null 2>&1 && ret=1
        if [ $ret != 0 ]; then echo "I:failed"; fi
        status=`expr $status + $ret`
done

for good in good*.conf
do
	n=`expr $n + 1`
        echo "I:checking that named-checkconf detects accepts $good ($n)"
        ret=0
        $CHECKCONF $good > /dev/null 2>&1 || ret=1
        if [ $ret != 0 ]; then echo "I:failed"; fi
        status=`expr $status + $ret`
done

n=`expr $n + 1`
echo "I:checking COOKIE token returned to empty COOKIE option ($n)"
ret=0
$DIG +qr +cookie version.bind txt ch @10.53.0.1 -p 5300 > dig.out.test$n
grep COOKIE: dig.out.test$n > /dev/null || ret=1
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking response size without COOKIE ($n)"
ret=0
$DIG large.example txt @10.53.0.1 -p 5300 +ignore > dig.out.test$n
havetc dig.out.test$n || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking response size without valid COOKIE ($n)"
ret=0
$DIG +cookie large.example txt @10.53.0.1 -p 5300 +ignore > dig.out.test$n
havetc dig.out.test$n || ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking response size with COOKIE ($n)"
ret=0
$DIG +cookie large.example txt @10.53.0.1 -p 5300 > dig.out.test$n.l
cookie=`getcookie dig.out.test$n.l`
$DIG +qr +cookie=$cookie large.example txt @10.53.0.1 -p 5300 +ignore > dig.out.test$n
havetc dig.out.test$n && ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking response size with COOKIE recursive ($n)"
ret=0
$DIG +qr +cookie=$cookie large.xxx txt @10.53.0.1 -p 5300 +ignore > dig.out.test$n
havetc dig.out.test$n && ret=1
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking COOKIE is learnt for TCP retry ($n)"
ret=0
$DIG +qr +cookie large.example txt @10.53.0.1 -p 5300 > dig.out.test$n
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 3 ]; then ret=1; fi
checkfull=`getcookie dig.out.test$n | fullcookie`
if [ $checkfull != 1 ]; then ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking for COOKIE value in adb ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 dumpdb
sleep 1
grep "10.53.0.2.*\[cookie=" ns1/named_dump.db > /dev/null|| ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking require-server-cookie default (no) ($n)"
ret=0
$DIG +qr +cookie +nobadcookie soa @10.53.0.1 -p 5300 > dig.out.test$n
grep BADCOOKIE dig.out.test$n > /dev/null && ret=1
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 2 ]; then ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking require-server-cookie yes ($n)"
ret=0
$DIG +qr +cookie +nobadcookie soa @10.53.0.3 -p 5300 > dig.out.test$n
grep "flags: qr[^;]* aa[ ;]" dig.out.test$n > /dev/null && ret=1
grep "flags: qr[^;]* ad[ ;]" dig.out.test$n > /dev/null && ret=1
grep BADCOOKIE dig.out.test$n > /dev/null || ret=1
linecount=`getcookie dig.out.test$n | wc -l`
if [ $linecount != 2 ]; then ret=1; fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

#
# Test shared cookie-secret support.
#
# NS4 has cookie-secret "569d36a6cc27d6bf55502183302ba352745255a2";
#
# NS5 has cookie-secret "569d36a6cc27d6bf55502183302ba352745255a2";
# NS5 has cookie-secret "6b300e27a0db46d4b046e4189790fa7db3c1ffb3"; (alternate)
#
# NS6 has cookie-secret "6b300e27a0db46d4b046e4189790fa7db3c1ffb3";
#
# Server cookies from NS4 are accepted by NS5 and not NS6
# Server cookies from NS5 are accepted by NS4 and not NS6
# Server cookies from NS6 are accepted by NS5 and not NS4
#
# Force local address so that the client's address is the same to all servers.
#

n=`expr $n + 1`
echo "I:get NS4 cookie for cross server checking ($n)"
ret=0
$DIG +cookie -b 10.53.0.4 soa . @10.53.0.4 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
ns4cookie=`getcookie dig.out.test$n`
test -n "$ns4cookie" || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:get NS5 cookie for cross server checking ($n)"
ret=0
$DIG +cookie -b 10.53.0.4 soa . @10.53.0.5 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
ns5cookie=`getcookie dig.out.test$n`
test -n "$ns5cookie" || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:get NS6 cookie for cross server checking ($n)"
ret=0
$DIG +cookie -b 10.53.0.4 soa . @10.53.0.6 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
ns6cookie=`getcookie dig.out.test$n`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS4 cookie on NS5 (expect success) ($n)"
ret=0
$DIG +cookie=$ns4cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.5 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS4 cookie on NS6 (expect badcookie) ($n)"
ret=0
$DIG +cookie=$ns4cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.6 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: BADCOOKIE," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS5 cookie on NS4 (expect success) ($n)"
ret=0
$DIG +cookie=$ns5cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.4 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS5 cookie on NS6 (expect badcookie) ($n)"
ret=0
$DIG +cookie=$ns5cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.6 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: BADCOOKIE," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS6 cookie on NS4 (expect badcookie) ($n)"
ret=0
$DIG +cookie=$ns6cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.4 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: BADCOOKIE," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:test NS6 cookie on NS5 (expect success) ($n)"
ret=0
$DIG +cookie=$ns6cookie -b 10.53.0.4 +nobadcookie soa . @10.53.0.5 -p 5300 > dig.out.test$n
grep "; COOKIE:.*(good)" dig.out.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
