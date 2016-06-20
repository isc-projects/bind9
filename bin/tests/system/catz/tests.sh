#!/bin/sh -x
#
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
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

status=0
n=0

n=`expr $n + 1`
echo "I:checking that dom1.example is not served by master ($n)"
ret=0
$DIG soa dom1.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding a domain dom1.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom1.example.db
echo "@ IN NS invalid." >> ns1/dom1.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom1.example '{type master; file "dom1.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom1.example is now served by master ($n)"
ret=0
$DIG soa dom1.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I:Adding domain dom1.example to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example 3600 IN PTR dom1.example.
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
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
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom1.example is served by slave ($n)"
ret=0
$DIG soa dom1.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Removing domain dom1.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
   server 10.53.0.1 5300
   update delete e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example
   send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
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
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom1.example is not served by slave ($n)"
ret=0
$DIG soa dom1.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding a domain dom2.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom2.example.db
echo "@ IN NS invalid." >> ns1/dom2.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom2.example '{type master; file "dom2.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding a domain dom5.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom5.example.db
echo "@ IN NS invalid." >> ns1/dom5.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom5.example '{type master; file "dom5.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding domains dom2.example, dom3.example and some trash to catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update add b901f492f3ebf6c1e5b597e51766f02f0479eb03.zones.catalog1.example 3600 IN PTR dom3.example.
    update add e721433b6160b450260d4f54b3ec8bab30cb3b83.zones.catalog1.example 3600 IN NS foo.bar.
    update add trash.catalog1.example 3600 IN A 1.2.3.4
    update add trash2.foo.catalog1.example 3600 IN A 1.2.3.4
    update add trash3.zones.catalog1.example 3600 IN NS a.dom2.example.
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding domains dom5.example to catalog2 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add de26b88d855397a03f77ff1162fd055d8b419584.zones.catalog2.example 3600 IN PTR dom5.example.
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom5.example' from catalog 'catalog2.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom5.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom5.example is served by slave ($n)"
ret=0
$DIG soa dom5.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I:checking that dom3.example is not served by master ($n)"
ret=0
$DIG soa dom3.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding a domain dom3.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom3.example.db
echo "@ IN NS invalid." >> ns1/dom3.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom3.example '{type master; file "dom3.example.db"; also-notify { 10.53.0.2; }; };' || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is served by master ($n)"
ret=0
$DIG soa dom2.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
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
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is served by slave ($n)"
ret=0
$DIG soa dom3.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding dom4.example with 'masters' defined and a random label ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add somerandomlabel.zones.catalog1.example 3600 IN PTR dom4.example.
    update add masters.somerandomlabel.zones.catalog1.example 3600 IN A 10.53.0.3
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom4.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom4.example/IN' from 10.53.0.3#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom4.example is served by slave ($n)"
ret=0
$DIG soa dom4.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Removing domain dom2.example from catalog1 zone ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete 636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: deleting zone 'dom2.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`


n=`expr $n + 1`
echo "I:checking that dom2.example is not served by slave ($n)"
ret=0
$DIG soa dom2.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is still served by slave ($n)"
ret=0
$DIG soa dom3.example @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that zone-directory is populated ($n)"
ret=0
[ -f "ns2/zonedir/__catz___default_catalog1.example_dom3.example.db" ] || ret=1
[ -f "ns2/zonedir/__catz___default_catalog1.example_dom4.example.db" ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that a missing zone directory forces in-memory ($n)"
ret=0
grep "'nonexistent' not found; zone files will not be saved" ns2/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:Adding a domain dom6.example to master via RNDC ($n)"
ret=0
echo "@ 3600 IN SOA . . 1 3600 3600 3600 3600" > ns1/dom6.example.db
echo "@ IN NS invalid." >> ns1/dom6.example.db
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953  addzone dom6.example '{type master; file "dom6.example.db";};' || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom6.example is now served by master ($n)"
ret=0
$DIG soa dom6.example @10.53.0.1 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`

n=`expr $n + 1`
echo "I:Adding domain dom6.example to catalog1 zone with an allow-query statement ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 4346f565b4d63ddb99e5d2497ff22d04e878e8f8.zones.catalog1.example 3600 IN PTR dom6.example.
    update add allow-query.4346f565b4d63ddb99e5d2497ff22d04e878e8f8.zones.catalog1.example 3600 IN APL 1:10.53.0.1/32 !1:10.53.0.0/30 1:0.0.0.0/0
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
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
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "transfer of 'dom6.example/IN' from 10.53.0.1#5300: Transfer status: success" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom6.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom6.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom6.example is not accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom6.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom6.example is accessible from 10.53.0.5 ($n)"
ret=0
$DIG soa dom6.example -b 10.53.0.5 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`
n=`expr $n + 1`
echo "I:Adding global allow-query and allow-domain ACLs ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update add 636722929740e507aaf27c502812fc395d30fb17.zones.catalog1.example 3600 IN PTR dom2.example.
    update add allow-query.catalog1.example 3600 IN APL 1:10.53.0.1/32
    update add allow-transfer.catalog1.example 3600 IN APL 1:10.53.0.2/32
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:waiting for slave to sync up ($n)"
ret=1
try=0
while test $try -lt 45
do
    sleep 1
    sed -n "$cur,"'$p' < ns2/named.run | grep "catz: adding zone 'dom2.example' from catalog 'catalog1.example'" > /dev/null && {
	ret=0
	break
    }
    try=`expr $try + 1`
done
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom3.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is not accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom3.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: REFUSED" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is not AXFR accessible from 10.53.0.1 ($n)"
ret=0
$DIG axfr dom3.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is AXFR accessible from 10.53.0.2 ($n)"
ret=0
$DIG axfr dom3.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

cur=`awk 'BEGIN {l=0} /^/ {l++} END { print l }' ns2/named.run`
n=`expr $n + 1`
echo "I:Deleting global allow-query and allow-domain ACLs ($n)"
ret=0
$NSUPDATE -d <<END >> nsupdate.out.test$n 2>&1 || ret=1
    server 10.53.0.1 5300
    update delete allow-query.catalog1.example 3600 IN APL 1:10.53.0.1/32
    update delete allow-transfer.catalog1.example 3600 IN APL 1:10.53.0.2/32
    send
END
if [ $ret != 0 ]; then echo "I:failed"; fi
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
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is accessible from 10.53.0.1 ($n)"
ret=0
$DIG soa dom3.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is accessible from 10.53.0.2 ($n)"
ret=0
$DIG soa dom3.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is AXFR accessible from 10.53.0.1 ($n)"
ret=0
$DIG axfr dom3.example -b 10.53.0.1 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I:checking that dom3.example is AXFR accessible from 10.53.0.2 ($n)"
ret=0
$DIG axfr dom3.example -b 10.53.0.2 @10.53.0.2 -p 5300 > dig.out.test$n
grep -v "Transfer failed." dig.out.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`



echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
