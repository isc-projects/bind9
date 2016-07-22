#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
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

echo "I: check for signed record ($n)"
ret=0
$DIG $DIGOPTS +norec example.  @10.53.0.1 TXT > dig.out.ns1.test$n || ret=1
grep "^example\.[ 	]*[0-9].*[ 	]*IN[ 	]*TXT[ 	]*\"This is a test\.\"" dig.out.ns1.test$n > /dev/null || ret=1
grep "^example\.[ 	]*[0-9].*[ 	]*IN[ 	]*RRSIG[ 	]*TXT[ 	]" dig.out.ns1.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check positive validation with valid trust anchor ($n)"
ret=0
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns2.test$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo "I: check positive validation using delv ($n)"
$DELV $DELVOPTS @10.53.0.1 txt example > delv.out$n || ret=1
grep "; fully validated" delv.out$n > /dev/null || ret=1	# redundant
grep "example..*TXT.*This is a test" delv.out$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" delv.out$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check for failed validation due to wrong key in managed-keys ($n)"
ret=0
$DIG $DIGOPTS +noauth example. @10.53.0.3 txt > dig.out.ns3.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns3.test$n > /dev/null && ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns3.test$n > /dev/null && ret=1
grep "opcode: QUERY, status: SERVFAIL, id" dig.out.ns3.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check new trust anchor can be added ($n)"
ret=0
standby1=`$KEYGEN -qfk -r $RANDFILE -K ns1 .`
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 5
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# there should be two keys listed now
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# one indicates current trust
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# one indicates pending trust
count=`grep -c "trust pending" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check new trust anchor can't be added with bad initial key ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.3 -p 9953 managed-keys refresh | sed 's/^/I: ns3 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.3 -p 9953 managed-keys sync | sed 's/^/I: ns3 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.3 -p 9953 managed-keys status > rndc.out.$n 2>&1
# there should be one key listed now
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# one line indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# ... and the key is not trusted
count=`grep -c "no trust" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: remove untrusted standby key, check timer restarts ($n)"
ret=0
$SETTIME -D now -K ns1 $standby1 > /dev/null
t1=`grep "trust pending" ns2/managed-keys.bind`
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
sleep 1
t2=`grep "trust pending" ns2/managed-keys.bind`
# trust pending date must be different
[ -n "$t2" ] || ret=1
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo "I: restore untrusted standby key, revoke original key ($n)"
t1=$t2
$SETTIME -D none -K ns1 $standby1 > /dev/null
$SETTIME -R now -K ns1 `cat ns1/managed.key` > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# trust is revoked
count=`grep -c "trust revoked" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# removal scheduled
count=`grep -c "remove at" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# trust is still pending on the standby key
count=`grep -c "trust pending" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# pending date moved forward for the standby key
t2=`grep "trust pending" ns2/managed-keys.bind`
[ -n "$t2" ] || ret=1
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo "I: refresh managed-keys, ensure same result ($n)"
t1=$t2
sleep 2
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# trust is revoked
count=`grep -c "trust revoked" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# removal scheduled
count=`grep -c "remove at" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# trust is still pending on the standby key
count=`grep -c "trust pending" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# pending date moved forward for the standby key
t2=`grep "trust pending" ns2/managed-keys.bind`
[ -n "$t2" ] || ret=1
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
ret=0
echo "I: restore revoked key, ensure same result ($n)"
t1=$t2
$SETTIME -R none -D now -K ns1 `cat ns1/managed.key` > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$SETTIME -D none -K ns1 `cat ns1/managed.key` > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# trust is revoked
count=`grep -c "trust revoked" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# removal scheduled
count=`grep -c "remove at" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# trust is still pending on the standby key
count=`grep -c "trust pending" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
# pending date moved forward for the standby key
t2=`grep "trust pending" ns2/managed-keys.bind`
[ -n "$t2" ] || ret=1
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: reinitialize trust anchors"
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc . ns2
rm -f ns2/managed-keys.bind*
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns2

n=`expr $n + 1`
echo "I: check that standby key is now trusted ($n)"
ret=0
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# both indicate current trust
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: revoke original key, add new standby ($n)"
ret=0
standby2=`$KEYGEN -qfk -r $RANDFILE -K ns1 .`
$SETTIME -R now -K ns1 `cat ns1/managed.key` > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# three keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 3 ] || ret=1
# one is revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# three lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 3 ] || ret=1
# one indicates current trust
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# one indicates revoked trust
count=`grep -c "trust revoked" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# one indicates trust pending
count=`grep -c "trust pending" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# removal scheduled
count=`grep -c "remove at" rndc.out.$n`
[ "$count" -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: revoke standby before it is trusted ($n)"
ret=0
standby3=`$KEYGEN -qfk -r $RANDFILE -K ns1 .`
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.a.$n 2>&1
# four keys listed
count=`grep -c "keyid: " rndc.out.a.$n` 
[ "$count" -eq 4 ] || { echo "keyid: count ($count) != 4"; ret=1; }
# one revoked
count=`grep -c "trust revoked" rndc.out.a.$n` 
[ "$count" -eq 1 ] || { echo "trust revoked count ($count) != 1"; ret=1; }
# two pending
count=`grep -c "trust pending" rndc.out.a.$n` 
[ "$count" -eq 2 ] || { echo "trust pending count ($count) != 2"; ret=1; }
$SETTIME -R now -K ns1 $standby3 > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.b.$n 2>&1
# now three keys listed
count=`grep -c "keyid: " rndc.out.b.$n` 
[ "$count" -eq 3 ] || { echo "keyid: count ($count) != 3"; ret=1; }
# one revoked
count=`grep -c "trust revoked" rndc.out.b.$n` 
[ "$count" -eq 1 ] || { echo "trust revoked count ($count) != 1"; ret=1; }
# one pending
count=`grep -c "trust pending" rndc.out.b.$n` 
[ "$count" -eq 1 ] || { echo "trust pending count ($count) != 1"; ret=1; }
$SETTIME -D now -K ns1 $standby3 > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: wait 15 seconds for key add/remove holddowns to expire ($n)"
ret=0
sleep 15
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# none revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 0 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# both indicate current trust
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: revoke all keys, confirm roll to insecure ($n)"
ret=0
$SETTIME -D now -K ns1 `cat ns1/managed.key` > /dev/null
$SETTIME -R now -K ns1 $standby1 > /dev/null
$SETTIME -R now -K ns1 $standby2 > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 loadkeys . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# two keys listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# both revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# two lines indicating trust status
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# both indicate trust revoked
count=`grep -c "trust revoked" rndc.out.$n` 
[ "$count" -eq 2 ] || ret=1
# both have removal scheduled
count=`grep -c "remove at" rndc.out.$n`
[ "$count" -eq 2 ] || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check for insecure response ($n)"
ret=0
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "status: NOERROR" dig.out.ns2.test$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I: reset the root server"
$SETTIME -D none -R none -K ns1 `cat ns1/managed.key` > /dev/null
$SETTIME -D now -K ns1 $standby1 > /dev/null
$SETTIME -D now -K ns1 $standby2 > /dev/null
$SIGNER -Sg -K ns1 -N unixtime -r $RANDFILE -o . ns1/root.db > /dev/null 2>&-
cp ns1/named2.conf ns1/named.conf
rm ns1/root.db.signed.jnl
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig

echo "I: reinitialize trust anchors"
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc . ns2
rm -f ns2/managed-keys.bind*
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns2

n=`expr $n + 1`
echo "I: check positive validation ($n)"
ret=0
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns2.test$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: revoke key with bad signature, check revocation is ignored ($n)"
ret=0
orig=`cat ns1/managed.key`
keyid=`cat ns1/managed.key.id`
revoked=`$REVOKE -K ns1 $orig`
rkeyid=`expr $revoked : 'ns1/K\.+00.+0*\([1-9]*[0-9]*[0-9]\)'`
$SETTIME -R none -D none -K ns1 $standby1 > /dev/null
$SIGNER -Sg -K ns1 -N unixtime -r $RANDFILE -O full -o . -f signer.out.$n ns1/root.db > /dev/null 2>&-
cp -f ns1/root.db.signed ns1/root.db.tmp
BADSIG="SVn2tLDzpNX2rxR4xRceiCsiTqcWNKh7NQ0EQfCrVzp9WEmLw60sQ5kP xGk4FS/xSKfh89hO2O/H20Bzp0lMdtr2tKy8IMdU/mBZxQf2PXhUWRkg V2buVBKugTiOPTJSnaqYCN3rSfV1o7NtC1VNHKKK/D5g6bpDehdn5Gaq kpBhN+MSCCh9OZP2IT20luS1ARXxLlvuSVXJ3JYuuhTsQXUbX/SQpNoB Lo6ahCE55szJnmAxZEbb2KOVnSlZRA6ZBHDhdtO0S4OkvcmTutvcVV+7 w53CbKdaXhirvHIh0mZXmYk2PbPLDY7PU9wSH40UiWPOB9f00wwn6hUe uEQ1Qg=="
sed -e "/ $rkeyid \./s, \. .*$, . $BADSIG," signer.out.$n > ns1/root.db.signed
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reload . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys sync | sed 's/^/I: ns2 /'
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# one key listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 1 ] || { echo "'keyid:' count ($count) != 1"; ret=1; }
# it's the original key id
count=`grep -c "keyid: $keyid" rndc.out.$n` 
[ "$count" -eq 1 ] || { echo "'keyid: $keyid' count ($count) != 1"; ret=1; }
# not revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 0 ] || { echo "'REVOKE' count ($count) != 0"; ret=1; }
# trust is still current
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 1 ] || { echo "'trust' count != 1"; ret=1; }
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 1 ] || { echo "'trusted since' count != 1"; ret=1; }
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check validation fails with bad DNSKEY rrset ($n)"
ret=0
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "status: SERVFAIL" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: restore DNSKEY rrset, check validation succeeds again ($n)"
ret=0
rm -f ${revoked}.key ${revoked}.private
$SETTIME -D none -R none -K ns1 `cat ns1/managed.key` > /dev/null
$SETTIME -D now -K ns1 $standby1 > /dev/null
$SETTIME -D now -K ns1 $standby2 > /dev/null
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 flush | sed 's/^/I: ns1 /'
sleep 1
$SIGNER -Sg -K ns1 -N unixtime -r $RANDFILE -o . ns1/root.db > /dev/null 2>&-
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reload . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns2.test$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: reset the root server with no keys, check for minimal update ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
t1=`grep 'next refresh:' rndc.out.$n`
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc . ns1
cp ns1/root.db ns1/root.db.signed
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns1
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# one key listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# it's the original key id
count=`grep -c "keyid: $keyid" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# not revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 0 ] || ret=1
# trust is still current
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
t2=`grep 'next refresh:' rndc.out.$n`
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: reset the root server with no signatures, check for minimal update ($n)"
t2=$t1
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc . ns1
cat ns1/K*.key >> ns1/root.db.signed
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns1
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
# one key listed
count=`grep -c "keyid: " rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# it's the original key id
count=`grep -c "keyid: $keyid" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
# not revoked
count=`grep -c "REVOKE" rndc.out.$n` 
[ "$count" -eq 0 ] || ret=1
# trust is still current
count=`grep -c "trust" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
count=`grep -c "trusted since" rndc.out.$n` 
[ "$count" -eq 1 ] || ret=1
t2=`grep 'next refresh:' rndc.out.$n`
[ "$t1" = "$t2" ] && ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: restore root server, check validation succeeds again ($n)"
rm ns1/root.db.signed.jnl
$SIGNER -Sg -K ns1 -N unixtime -r $RANDFILE -o . ns1/root.db > /dev/null 2>&-
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reload . | sed 's/^/I: ns1 /'
sleep 3
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys refresh | sed 's/^/I: ns2 /'
sleep 1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 managed-keys status > rndc.out.$n 2>&1
$DIG $DIGOPTS +noauth example. @10.53.0.2 txt > dig.out.ns2.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns2.test$n > /dev/null || ret=1
grep "example..*.RRSIG..*TXT" dig.out.ns2.test$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check that trust-anchor-telemetry queries are logged ($n)"
ret=0
grep "sending trust-anchor-telemetry query '_ta-[0-9a-f]*/NULL" ns3/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo "I: check that trust-anchor-telemetry queries are received ($n)"
ret=0
grep "query '_ta-[0-9a-f]*/NULL/IN' approved" ns1/named.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
