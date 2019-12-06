# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="-p ${PORT}"
SENDCMD="$PERL ../send.pl 10.53.0.6 $EXTRAPORT1"

root=10.53.0.1
hidden=10.53.0.2
f1=10.53.0.3
f2=10.53.0.4

status=0
n=0

n=$((n+1))
echo_i "checking that a forward zone overrides global forwarders ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example1. txt @$hidden > dig.out.$n.hidden || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example1. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forward first zone no forwarders recurses ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.root dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forward only zone no forwarders fails ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.root dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that global forwarders work ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example4. txt @$hidden > dig.out.$n.hidden || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example4. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forward zone works ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example1. txt @$hidden > dig.out.$n.hidden || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example1. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that forwarding doesn't spontaneously happen ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example2. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.root dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forward zone with no specified policy works ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example3. txt @$hidden > dig.out.$n.hidden || ret=1
$DIG $DIGOPTS +noadd +noauth txt.example3. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forward only doesn't recurse ($n)"
ret=0
$DIG $DIGOPTS txt.example5. txt @$f2 > dig.out.$n.f2 || ret=1
grep "SERVFAIL" dig.out.$n.f2 > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking for negative caching of forwarder response ($n)"
# prime the cache, shutdown the forwarder then check that we can
# get the answer from the cache.  restart forwarder.
ret=0
$DIG $DIGOPTS nonexist. txt @10.53.0.5 > dig.out.$n.f2 || ret=1
grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null || ret=1
$PERL ../stop.pl forward ns4 || ret=1
$DIG $DIGOPTS nonexist. txt @10.53.0.5 > dig.out.$n.f2 || ret=1
grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null || ret=1
$PERL ../start.pl --restart --noclean --port ${PORT} forward ns4 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that forward only zone overrides empty zone ($n)"
ret=0
# retry loop in case the server restart above causes transient failure
for try in 0 1 2 3 4 5 6 7 8 9; do
    $DIG $DIGOPTS 1.0.10.in-addr.arpa TXT @10.53.0.4 > dig.out.$n.f2
    grep "status: NOERROR" dig.out.$n.f2 > /dev/null || ret=1
    $DIG $DIGOPTS 2.0.10.in-addr.arpa TXT @10.53.0.4 > dig.out.$n.f2
    grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null || ret=1
    [ "$ret" -eq 0 ] && break
    sleep 1
done
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that DS lookups for grafting forward zones are isolated ($n)"
ret=0
$DIG $DIGOPTS grafted A @10.53.0.4 > dig.out.$n.q1
$DIG $DIGOPTS grafted DS @10.53.0.4 > dig.out.$n.q2
$DIG $DIGOPTS grafted A @10.53.0.4 > dig.out.$n.q3
$DIG $DIGOPTS grafted AAAA @10.53.0.4 > dig.out.$n.q4
grep "status: NOERROR" dig.out.$n.q1 > /dev/null || ret=1
grep "status: NXDOMAIN" dig.out.$n.q2 > /dev/null || ret=1
grep "status: NOERROR" dig.out.$n.q3 > /dev/null || ret=1
grep "status: NOERROR" dig.out.$n.q4 > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that rfc1918 inherited 'forward first;' zones are warned about ($n)"
ret=0
$CHECKCONF rfc1918-inherited.conf | grep "forward first;" >/dev/null || ret=1
$CHECKCONF rfc1918-notinherited.conf | grep "forward first;" >/dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that ULA inherited 'forward first;' zones are warned about ($n)"
ret=0
$CHECKCONF ula-inherited.conf | grep "forward first;" >/dev/null || ret=1
$CHECKCONF ula-notinherited.conf | grep "forward first;" >/dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that a forwarder timeout prevents it from being reused in the same fetch context ($n)"
ret=0
# Make ans6 receive queries without responding to them.
echo "//" | $SENDCMD
# Query for a record in a zone which is forwarded to a non-responding forwarder
# and is delegated from the root to check whether the forwarder will be retried
# when a delegation is encountered after falling back to full recursive
# resolution.
$DIG $DIGOPTS txt.example7. txt @$f1 > dig.out.$n.f1 || ret=1
# The forwarder for the "example7" zone should only be queried once.
sent=`tr -d '\r' < ns3/named.run | sed -n '/sending packet to 10.53.0.6/,/^$/p' | grep ";txt.example7.*IN.*TXT" | wc -l`
if [ $sent -ne 1 ]; then ret=1; fi
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that priming queries are not forwarded ($n)"
ret=0
$DIG $DIGOPTS +noadd +noauth txt.example1. txt @10.53.0.7 > dig.out.$n.f7 || ret=1
sent=`tr -d '\r' < ns7/named.run | sed -n '/sending packet to 10.53.0.1/,/^$/p' | grep ";.*IN.*NS" | wc -l`
[ $sent -eq 1 ] || ret=1
sent=`grep "10.53.0.7#.* (.): query '\./NS/IN' approved" ns4/named.run | wc -l`
[ $sent -eq 0 ] || ret=1
sent=`grep "10.53.0.7#.* (.): query '\./NS/IN' approved" ns1/named.run | wc -l`
[ $sent -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking recovery from forwarding to a non-recursive server ($n)"
ret=0
$DIG $DIGOPTS xxx.sld.tld txt @10.53.0.8  > dig.out.$n.f8
grep "status: NOERROR" dig.out.$n.f8 > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
