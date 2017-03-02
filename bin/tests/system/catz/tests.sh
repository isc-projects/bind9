#!/bin/sh -x
#
# Copyright (C) 2016, 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0
##########################################################################
echo "I:Testing adding/removing of domain in catalog zone"
n=`expr $n + 1`
echo "I: checking that dom1.example is not served by master ($n)"
ret=0
$DIG soa dom1.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom1.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom1.example.db
echo "@ IN NS invalid." >> ns1/dom1.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom1.example '{type master; file "dom1.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom1.example is now served by master ($n)"
ret=0
$DIG soa dom1.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain dom1.example to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example 3600 IN PTR dom1.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom1.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom1.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom1.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom1.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that zone-directory is populated ($n)"
ret=0
[ -f "ns2/zonedir/__catz___default_catalog1.example_dom1.example.db" ] || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing domain dom1.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
   server 10.53.0.1 5300
   update delete e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example
   send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom1.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom1.example is not served by slave ($n)"
ret=0
$DIG soa dom1.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that zone-directory is emptied ($n)"
ret=0
[ -f "ns2/zonedir/__catz___default_catalog1.example_dom1.example.db" ] && ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing various simple operations on domains, including using multiple catalog zones and garbage in zone"
n=`expr $n + 1`
echo "I: adding domain dom2.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom2.example.db
echo "@ IN NS invalid." >> ns1/dom2.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom2.example '{type master; file "dom2.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: adding domain dom4.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom4.example.db
echo "@ IN NS invalid." >> ns1/dom4.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom4.example '{type master; file "dom4.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: adding domains dom2.example, dom3.example and some garbage to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update add b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN PTR dom3.example.
    update add e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example 3600 IN NS foo.bar.
    update add trash.catalog1.example 3600 IN A 1.2.3.4
    update add trash2.foo.catalog1.example 3600 IN A 1.2.3.4
    update add trash3.zones.catalog1.example 3600 IN NS a.dom2.example.
    update add foobarbaz.b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN PTR dom3.example.
    update add blahblah.636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update add foobarbaz.b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN APL 1:1.2.3.4/30
    update add blahblah.636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN TXT "blah blah"
    update add version.catalog1.example 3600 IN A 1.2.3.4
    send

END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: adding domain dom4.example to catalog2 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update add de26b88d855397a03f77ff1162fd055d8b419584.zones.catalog2.example 3600 IN PTR dom4.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom4.example' from catalog 'catalog2.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom4.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom4.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom4.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I: checking that dom3.example is not served by master ($n)"
ret=0
$DIG soa dom3.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: adding a domain dom3.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom3.example.db
echo "@ IN NS invalid." >> ns1/dom3.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom3.example '{type master; file "dom3.example.db"; also-notify { 10.53.0.2; }; notify explicit; };' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom3.example is served by master ($n)"
ret=0
$DIG soa dom3.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom3.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom3.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom3.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom3.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing all records from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete 636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update delete b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN PTR dom3.example.
    update delete e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example 3600 IN NS foo.bar.
    update delete trash.catalog1.example 3600 IN A 1.2.3.4
    update delete trash2.foo.catalog1.example 3600 IN A 1.2.3.4
    update delete trash3.zones.catalog1.example 3600 IN NS a.dom2.example.
    update delete foobarbaz.b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN PTR dom3.example.
    update delete blahblah.636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update delete foobarbaz.b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN APL 1:1.2.3.4/30
    update delete blahblah.636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN TXT "blah blah"
    update delete version.catalog1.example 3600 IN A 1.2.3.4
    send

END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing all records from catalog2 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update delete de26b88d855397a03f77ff1162fd055d8b419584.zones.catalog2.example 3600 IN PTR dom4.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing masters suboption and random labels"
n=`expr $n + 1`
echo "I: adding dom5.example with 'masters' suboption set and a random label ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add somerandomlabel.zones.catalog1.example 3600 IN PTR dom5.example.
    update add masters.somerandomlabel.zones.catalog1.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom5.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done

try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom5.example/IN' from 10.53.0.3#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom5.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom5.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing dom5.example ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete somerandomlabel.zones.catalog1.example 3600 IN PTR dom5.example.
    update delete masters.somerandomlabel.zones.catalog1.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom5.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom5.example is no longer served by slave ($n)"
ret=0
$DIG soa dom5.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


##########################################################################
echo "I:Testing masters global option"
n=`expr $n + 1`
echo "I: adding dom6.example and global masters option ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add masters.catalog1.example 3600 IN A 10.53.0.3
    update add masters.catalog1.example 3600 IN AAAA  fd92:7065:b8e:ffff::3
    update add 4346f565b4d63ddb99e5d2497ff22d04e878e8f8.zones.catalog1.example 3600 IN PTR dom6.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom6.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done

try=0
while test $try -lt 120
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom6.example/IN' from " > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom6.example is served by slave ($n)"
try=0
while test $try -lt 150
do
    $DIG soa dom6.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing dom6.example ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete masters.catalog1.example 3600 IN A 10.53.0.3
    update delete masters.catalog1.example 3600 IN AAAA  fd92:7065:b8e:ffff::3
    update delete 4346f565b4d63ddb99e5d2497ff22d04e878e8f8.zones.catalog1.example 3600 IN PTR dom6.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom6.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom6.example is no longer served by slave ($n)"
ret=0
$DIG soa dom6.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


##########################################################################
n=`expr $n + 1`
echo "I:Checking that a missing zone directory forces in-memory ($n)"
ret=0
grep "'nonexistent' not found; zone files will not be saved" ns2/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing allow-query and allow-transfer ACLs"
n=`expr $n + 1`
echo "I: adding domains dom7.example and dom8.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom7.example.db
echo "@ IN NS invalid." >> ns1/dom7.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom7.example '{type master; file "dom7.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom8.example.db
echo "@ IN NS invalid." >> ns1/dom8.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom8.example '{type master; file "dom8.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom7.example is now served by master ($n)"
ret=0
$DIG soa dom7.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: adding domain dom7.example to catalog1 zone with an allow-query statement ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 78833ec3c0059fd4540fee81c7eaddce088e7cd7.zones.catalog1.example 3600 IN PTR dom7.example.
    update add allow-query.78833ec3c0059fd4540fee81c7eaddce088e7cd7.zones.catalog1.example 3600 IN APL 1:10.53.0.1/32 !1:10.53.0.0/30 1:0.0.0.0/0
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom7.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom7.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom7.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom7.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom7.example is not accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom7.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom7.example is accessible from 10.53.0.5 ($n)"
ret=0
$DIG soa dom7.example -b 10.53.0.5 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`
n=`expr $n + 1`
echo "I: adding dom8.example domain and global allow-query and allow-transfer ACLs ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add cba95222e308baba42417be6021026fdf20827b6.zones.catalog1.example 3600 IN PTR dom8.example
    update add allow-query.catalog1.example 3600 IN APL 1:10.53.0.1/32
    update add allow-transfer.catalog1.example 3600 IN APL 1:10.53.0.2/32
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom8.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is not accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom8.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is not AXFR accessible from 10.53.0.1 ($n)"
ret=0
$DIG axfr dom8.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is AXFR accessible from 10.53.0.2 ($n)"
ret=0
$DIG axfr dom8.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`
n=`expr $n + 1`
echo "I: deleting global allow-query and allow-domain ACLs ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete allow-query.catalog1.example 3600 IN APL 1:10.53.0.1/32
    update delete allow-transfer.catalog1.example 3600 IN APL 1:10.53.0.2/32
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
ret=0
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom8.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom8.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is AXFR accessible from 10.53.0.1 ($n)"
ret=0
$DIG axfr dom8.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom8.example is AXFR accessible from 10.53.0.2 ($n)"
ret=0
$DIG axfr dom8.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


##########################################################################
echo "I:Testing TSIG keys for masters set per-domain"
n=`expr $n + 1`
echo "I: adding a domain dom9.example to master via RNDC, with transfers allowed only with TSIG key ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom9.example.db
echo "@ IN NS invalid." >> ns1/dom9.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 addzone dom9.example '{type master; file "dom9.example.db"; allow-transfer { key tsig_key; }; };' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom9.example is now served by master ($n)"
ret=0
$DIG soa dom9.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: adding domain dom9.example to catalog1 zone with masters and tsig key($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN PTR dom9.example.
    update add label1.masters.f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN A 10.53.0.1
    update add label1.masters.f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN TXT "tsig_key"
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom9.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom9.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom9.example is accessible on slave ($n)"
ret=0
$DIG soa dom9.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: deleting domain dom9.example from catalog1 zone($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN PTR dom9.example.
    update delete label1.masters.f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN A 10.53.0.1
    update delete label1.masters.f0f989bc71c5c8ca3a1eb9c9ab5246521907e3af.zones.catalog1.example 3600 IN TXT "tsig_key"
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom9.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom9.example is no longer accessible on slave ($n)"
ret=0
$DIG soa dom9.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing very long domain in catalog"
n=`expr $n + 1`
echo "I: checking that this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example is not served by master ($n)"
ret=0
$DIG soa this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom10.example.db
echo "@ IN NS invalid." >> ns1/dom10.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example '{type master; file "dom10.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example is now served by master ($n)"
ret=0
$DIG soa this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 825f48b1ce1b4cf5a041d20255a0c8e98d114858.zones.catalog1.example 3600 IN PTR this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example is served by slave ($n)"
ret=0
$DIG soa this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that zone-directory is populated with a hashed filename($n)"
ret=0
[ -f "ns2/zonedir/__catz__4d70696f2335687069467f11f5d5378c480383f97782e553fb2d04a7bb2a23ed.db" ] || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing domain this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
   server 10.53.0.1 5300
   update delete 825f48b1ce1b4cf5a041d20255a0c8e98d114858.zones.catalog1.example
   send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example is not served by slave ($n)"
ret=0
$DIG soa this.is.a.very.very.long.long.long.domain.that.will.cause.catalog.zones.to.generate.hash.instead.of.using.regular.filename.dom10.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that zone-directory is emptied ($n)"
ret=0
[ -f "ns2/zonedir/__catz__4d70696f2335687069467f11f5d5378c480383f97782e553fb2d04a7bb2a23ed.db" ] && ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing adding a domain and a subdomain of it"
n=`expr $n + 1`
echo "I: checking that dom11.example is not served by master ($n)"
ret=0
$DIG soa dom11.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom11.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom11.example.db
echo "@ IN NS invalid." >> ns1/dom11.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom11.example '{type master; file "dom11.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom11.example is now served by master ($n)"
ret=0
$DIG soa dom11.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain dom11.example to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 0580d70e769c86c8b951a488d8b776627f427d7a.zones.catalog1.example 3600 IN PTR dom11.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom11.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom11.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom11.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom11.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that subdomain.of.dom11.example is not served by master ($n)"
ret=0
$DIG soa subdomain.of.dom11.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NXDOMAIN" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain subdomain.of.dom11.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/subdomain.of.dom11.example.db
echo "@ IN NS invalid." >> ns1/subdomain.of.dom11.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone subdomain.of.dom11.example '{type master; file "subdomain.of.dom11.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that subdomain.of.dom11.example is now served by master ($n)"
ret=0
$DIG soa subdomain.of.dom11.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain subdomain.of.dom11.example to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 25557e0bdd10cb3710199bb421b776df160f241e.zones.catalog1.example 3600 IN PTR subdomain.of.dom11.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'subdomain.of.dom11.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'subdomain.of.dom11.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that subdomain.of.dom11.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa subdomain.of.dom11.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`



n=`expr $n + 1`
echo "I: removing domain dom11.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
   server 10.53.0.1 5300
   update delete 0580d70e769c86c8b951a488d8b776627f427d7a.zones.catalog1.example
   send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom11.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom11.example is not served by slave ($n)"
ret=0
$DIG soa dom11.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that subdomain.of.dom11.example is still served by slave ($n)"
ret=0
$DIG soa subdomain.of.dom11.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing domain subdomain.of.dom11.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
   server 10.53.0.1 5300
   update delete 25557e0bdd10cb3710199bb421b776df160f241e.zones.catalog1.example
   send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'subdomain.of.dom11.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that subdomain.of.dom11.example is not served by slave ($n)"
ret=0
$DIG soa subdomain.of.dom11.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


##########################################################################
echo "I:Testing adding a catalog zone at runtime with rndc reconfig"
n=`expr $n + 1`
echo "I: checking that dom12.example is not served by master ($n)"
ret=0
$DIG soa dom12.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom12.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom12.example.db
echo "@ IN NS invalid." >> ns1/dom12.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom12.example '{type master; file "dom12.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom12.example is now served by master ($n)"
ret=0
$DIG soa dom12.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain dom12.example to catalog4 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 871d51e5433543c0f6fb263c40f359fbc152c8ae.zones.catalog4.example 3600 IN PTR dom12.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom12.example is not served by slave ($n)"
ret=0
$DIG soa dom12.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I: reconfiguring slave - adding catalog4 catalog zone ($n)"
ret=0
cat ns2/named.conf.in |sed -e "s/^#T1//g" > ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom12.example' from catalog 'catalog4.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom12.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom12.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom12.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: reconfiguring slave - removing catalog4 catalog zone ($n)"
ret=0
cat ns2/named.conf.in > ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom12.example is not served by slave ($n)"
ret=0
$DIG soa dom12.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: removing domain dom12.example from catalog4 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete 871d51e5433543c0f6fb263c40f359fbc152c8ae.zones.catalog4.example 3600 IN PTR dom12.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing having a zone in two different catalogs"
n=`expr $n + 1`
echo "I: checking that dom13.example is not served by master ($n)"
ret=0
$DIG soa dom13.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom13.example to master ns1 via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom13.example.db
echo "@ IN NS invalid." >> ns1/dom13.example.db
echo "@ IN A 192.0.2.1" >> ns1/dom13.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom13.example '{type master; file "dom13.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom13.example is now served by master ns1 ($n)"
ret=0
$DIG soa dom13.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom13.example to master ns3 via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns3/dom13.example.db
echo "@ IN NS invalid." >> ns3/dom13.example.db
echo "@ IN A 192.0.2.2" >> ns3/dom13.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.3 -p 9953 addzone dom13.example '{type master; file "dom13.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom13.example is now served by master ns3 ($n)"
ret=0
$DIG soa dom13.example @10.53.0.3 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`


cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain dom13.example to catalog1 zone with ns1 as master($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog1.example 3600 IN PTR dom13.example.
    update add masters.8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog1.example 3600 IN A 10.53.0.1
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom13.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom13.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: checking that dom13.example is served by slave and that it's the one from ns1 ($n)"
ret=0
$DIG a dom13.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding domain dom13.example to catalog2 zone with ns3 as master($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update add 8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog2.example 3600 IN PTR dom13.example.
    update add masters.8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog2.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom13.example is served by slave and that it's still the one from ns1 ($n)"
ret=0
$DIG a dom13.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Deleting domain dom13.example from catalog2 ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update delete 8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog2.example 3600 IN PTR dom13.example.
    update delete masters.8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog2.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom13.example is served by slave and that it's still the one from ns1 ($n)"
ret=0
$DIG a dom13.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Deleting domain dom13.example from catalog1 ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete 8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog1.example 3600 IN PTR dom13.example.
    update delete masters.8d7989c746b3f92b3bba2479e72afd977198363f.zones.catalog1.example 3600 IN A 10.53.0.2
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom13.example is no longer served by slave ($n)"
ret=0
$DIG a dom13.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing having a regular zone and a zone in catalog zone of the same name"
n=`expr $n + 1`
echo "I: checking that dom14.example is not served by master ($n)"
ret=0
$DIG soa dom14.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom14.example to master ns1 via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom14.example.db
echo "@ IN NS invalid." >> ns1/dom14.example.db
echo "@ IN A 192.0.2.1" >> ns1/dom14.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom14.example '{type master; file "dom14.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom14.example is now served by master ns1 ($n)"
ret=0
$DIG soa dom14.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom14.example to master ns3 via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns3/dom14.example.db
echo "@ IN NS invalid." >> ns3/dom14.example.db
echo "@ IN A 192.0.2.2" >> ns3/dom14.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.3 -p 9953 addzone dom14.example '{type master; file "dom14.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom14.example is now served by master ns3 ($n)"
ret=0
$DIG soa dom14.example @10.53.0.3 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Adding domain dom14.example with rndc with ns1 as master($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone dom14.example '{type slave; masters {10.53.0.1;};};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom14.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: checking that dom14.example is served by slave and that it's the one from ns1 ($n)"
ret=0
$DIG a dom14.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding domain dom14.example to catalog2 zone with ns3 as master($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update add 45e3d45ea5f7bd01c395ccbde6ae2e750a3ee8ab.zones.catalog2.example 3600 IN PTR dom14.example.
    update add masters.45e3d45ea5f7bd01c395ccbde6ae2e750a3ee8ab.zones.catalog2.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom14.example is served by slave and that it's still the one from ns1 ($n)"
ret=0
$DIG a dom14.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Deleting domain dom14.example from catalog2 ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.3 5300
    update delete 45e3d45ea5f7bd01c395ccbde6ae2e750a3ee8ab.zones.catalog2.example 3600 IN PTR dom14.example.
    update delete masters.45e3d45ea5f7bd01c395ccbde6ae2e750a3ee8ab.zones.catalog2.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom14.example is served by slave and that it's still the one from ns1 ($n)"
ret=0
$DIG a dom14.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
grep "192.0.2.1" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

##########################################################################
echo "I:Testing changing label for a member zone"
n=`expr $n + 1`
echo "I: checking that dom15.example is not served by master ($n)"
ret=0
$DIG soa dom15.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: Adding a domain dom15.example to master ns1 via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom15.example.db
echo "@ IN NS invalid." >> ns1/dom15.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom15.example '{type master; file "dom15.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom15.example is now served by master ns1 ($n)"
ret=0
$DIG soa dom15.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

echo "I: Adding domain dom15.example to catalog1 zone with 'dom15label1' label ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add dom15label1.zones.catalog1.example 3600 IN PTR dom15.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

sleep 3

n=`expr $n + 1`
echo "I: checking that dom15.example is served by slave($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom15.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I: Changing label of domain dom15.example from 'dom15label1' to 'dom15label2' ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete dom15label1.zones.catalog1.example 3600 IN PTR dom15.example.
    update add dom15label2.zones.catalog1.example 3600 IN PTR dom15.example.
    send
END
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: update_from_db: new zone merged" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: checking that dom15.example is served by slave ($n)"
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG soa dom15.example @10.53.0.2 -p 5300 > dig.out.test$n
    ret=0
    grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
