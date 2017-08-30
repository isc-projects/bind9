#!/bin/sh
#
# Copyright (C) 2000-2002, 2004-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=1

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +nocmd +dnssec -p 5300"
DELVOPTS="-a ns1/trusted.conf -p 5300"

echo "I:prime negative NXDOMAIN response ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NXDOMAIN," dig.out.ns2.test$n > /dev/null || ret=1
grep "example.*3600.IN.SOA" dig.out.ns2.test$n > /dev/null || ret=1
nxdomain=dig.out.ns2.test$n
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:prime negative NODATA response ($n)"
ret=0
$DIG $DIGOPTS nodata.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "example.*3600.IN.SOA" dig.out.ns2.test$n > /dev/null || ret=1
nodata=dig.out.ns2.test$n
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:prime wildcard response ($n)"
ret=0
$DIG $DIGOPTS a.wild-a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "a.wild-a.example.*3600.IN.A" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:prime wildcard CNAME response ($n)"
ret=0
$DIG $DIGOPTS a.wild-cname.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "a.wild-cname.example.*3600.IN.CNAME" dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:prime redirect response (+nodnssec) ($n)"
ret=0
$DIG $DIGOPTS +nodnssec a.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null && ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep 'a\.redirect\..*300.IN.A.100\.100\.100\.2' dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

sleep 1

$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 dumpdb

echo "I:check synthesized NXDOMAIN response ($n)"
ret=0
$DIG $DIGOPTS b.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NXDOMAIN," dig.out.ns2.test$n > /dev/null || ret=1
grep "example.*3600.IN.SOA" dig.out.ns2.test$n > /dev/null && ret=1
$PERL ../digcomp.pl $nxdomain dig.out.ns2.test$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:check synthesized NODATA response ($n)"
ret=0
$DIG $DIGOPTS nodata.example. @10.53.0.2 aaaa > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "example.*3600.IN.SOA" dig.out.ns2.test$n > /dev/null && ret=1
$PERL ../digcomp.pl $nodata dig.out.ns2.test$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed (ignored - to be supported in the future)"; fi
: status=`expr $status + $ret`

echo "I:check synthesized wildcard response ($n)"
ret=0
$DIG $DIGOPTS b.wild-a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "b\.wild-a\.example\..*3600.IN.A" dig.out.ns2.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed (ignored - to be supported in the future)"; fi
: status=`expr $status + $ret`

echo "I:check synthesized wildcard CNAME response ($n)"
ret=0
$DIG $DIGOPTS b.wild-cname.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep "b.wild-cname.example.*3600.IN.CNAME" dig.out.ns2.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed (ignored - to be supported in the future)"; fi
: status=`expr $status + $ret`

echo "I:check redirect response (+dnssec) ($n)"
ret=0
$DIG $DIGOPTS b.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NXDOMAIN," dig.out.ns2.test$n > /dev/null || ret=1
grep "\..*3600.IN.SOA" dig.out.ns2.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:check redirect response (+nodnssec) ($n)"
ret=0
$DIG $DIGOPTS +nodnssec b.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null && ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep 'b\.redirect\..*300.IN.A.100\.100\.100\.2' dig.out.ns2.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
