#!/bin/sh
#
# Copyright (C) 2010-2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noauth +noadd +nostats +dnssec -p 5300"
status=0
n=0

echo "I:checking normally loaded zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# When LMDB support is compiled in, this tests that migration from
# NZF to NZD occurs during named startup
echo "I:checking previously added zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

if [ -n "$NZD" ]; then
    echo "I:checking that existing NZF file was renamed after migration ($n)"
    [ -e ns2/3bf305731dd26307.nzf~ ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

echo "I:adding new zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking addzone errors are logged correctly"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone bad.example '{ type mister; };' 2>&1 | grep 'unexpected token' > /dev/null 2>&1 || ret=1
grep "addzone: 'mister' unexpected" ns2/named.run >/dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking modzone errors are logged correctly"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 modzone added.example '{ type mister; };' 2>&1 | grep 'unexpected token' > /dev/null 2>&1 || ret=1
grep "modzone: 'mister' unexpected" ns2/named.run >/dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:adding a zone that requires quotes ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone '"32/1.0.0.127-in-addr.added.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 "a.32/1.0.0.127-in-addr.added.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.32/1.0.0.127-in-addr.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:adding a zone with a quote in the name ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone '"foo\"bar.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.foo\\"bar.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:adding new zone with missing master file ($n)"
ret=0
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.pre.$n || ret=1
grep "status: REFUSED" dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'missing.example { type master; file "missing.db"; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.post.$n || ret=1
grep "status: REFUSED" dig.out.ns2.post.$n > /dev/null || ret=1
$PERL ../digcomp.pl dig.out.ns2.pre.$n dig.out.ns2.post.$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

if [ -z "$NZD" ]; then
    echo "I:verifying no comments in NZF file ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
    [ $hcount -eq 0 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

echo "I:checking rndc showzone with previously added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 showzone previous.example > rndc.out.ns2.$n
expected='zone "previous.example" { type master; file "previous.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting previously added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone previous.example 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

if [ -z "$NZD" ]; then
    echo "I:checking NZF file now has comment ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
    [ $hcount -eq 1 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

echo "I:deleting newly added zone added.example ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone added.example 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting newly added zone with escaped quote ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone "foo\\\"bar.example" 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep "^a.foo\"bar.example" dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking rndc showzone with a normally-loaded zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 showzone normal.example > rndc.out.ns2.$n
expected='zone "normal.example" { type master; file "normal.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking rndc showzone with a normally-loaded zone with trailing dot ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 showzone finaldot.example > rndc.out.ns2.$n
expected='zone "finaldot.example." { type master; file "normal.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:delete a normally-loaded zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone normal.example 2> rndc.out.ns2.$n
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to add master zone with inline signing ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'inline.example { type master; file "inline.db"; inline-signing yes; };' 2>&1 | sed 's/^/I:ns2 /'
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inline.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inline.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to add master zone with inline signing and missing master ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'inlinemissing.example { type master; file "missing.db"; inline-signing yes; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to add slave zone with inline signing ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'inlineslave.example { type slave; masters { 10.53.0.1; }; file "inlineslave.bk"; inline-signing yes; };' 2>&1 | sed 's/^/I:ns2 /'
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inlineslave.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inlineslave.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to delete slave zone with inline signing ($n)"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && break
	sleep 1
done
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone inlineslave.example 2>&1 > rndc.out2.test$n
test -f inlineslave.bk ||
grep '^inlineslave.bk$' rndc.out2.test$n > /dev/null || {
	echo "I:failed to report inlineslave.bk"; ret=1;
}
test ! -f inlineslave.bk.signed ||
grep '^inlineslave.bk.signed$' rndc.out2.test$n > /dev/null || {
	echo "I:failed to report inlineslave.bk.signed"; ret=1;
}
n=`expr $n + 1`
status=`expr $status + $ret`

echo "I:restoring slave zone with inline signing ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'inlineslave.example { type slave; masters { 10.53.0.1; }; file "inlineslave.bk"; inline-signing yes; };' 2>&1 | sed 's/^/I:ns2 /'
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inlineslave.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inlineslave.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting slave zone with automatic zone file removal ($n)"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && break
	sleep 1
done
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone -clean inlineslave.example 2>&1 > /dev/null
for i in 0 1 2 3 4 5 6 7 8 9
do
        ret=0
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && ret=1
        [ $ret = 0 ] && break
	sleep 1
done
n=`expr $n + 1`
status=`expr $status + $ret`

echo "I:modifying zone configuration ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'mod.example { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG +norec $DIGOPTS @10.53.0.2 mod.example ns > dig.out.ns2.1.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.1.$n > /dev/null || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 modzone 'mod.example { type master; file "added.db"; allow-query { none; }; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG +norec $DIGOPTS @10.53.0.2 mod.example ns > dig.out.ns2.2.$n || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 showzone mod.example | grep 'allow-query { "none"; };' > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:reconfiguring server with multiple views"
rm -f ns2/named.conf 
cp -f ns2/named2.conf ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig 2>&1 | sed 's/^/I:ns2 /'
sleep 5

echo "I:adding new zone to external view ($n)"
# NOTE: The internal view has "recursion yes" set, and so queries for
# nonexistent zones should return NOERROR.  The external view is
# "recursion no", so queries for nonexistent zones should return
# REFUSED.  This behavior should be the same regardless of whether
# the zone does not exist because a) it has not yet been loaded, b)
# it failed to load, or c) it has been deleted.
ret=0
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.intpre.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.intpre.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.extpre.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.extpre.$n > /dev/null || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example in external { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

if [ -z "$NZD" ]; then
    echo "I:checking new NZF file has comment ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: external" ns2/external.nzf | wc -l`
    [ $hcount -eq 1 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

if [ -n "$NZD" ]; then
    echo "I:verifying added.example in external view created an external.nzd DB ($n)"
    ret=0
    [ -e ns2/external.nzd ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo "I:failed"; fi
    status=`expr $status + $ret`
fi

echo "I:checking rndc reload causes named to reload the external view's new zone config ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reload 2>&1 | sed 's/^/I:ns2 /'
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking rndc showzone with newly added zone ($n)"
# loop because showzone may complain if zones are still being
# loaded from the NZDB at this point.
for try in 0 1 2 3 4 5; do
    ret=0
    $RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 showzone added.example in external > rndc.out.ns2.$n
    if [ -z "$NZD" ]; then
      expected='zone "added.example" in external { type master; file "added.db"; };'
    else
      expected='zone "added.example" { type master; file "added.db"; };'
    fi
    [ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting newly added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone 'added.example in external' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to add zone to internal view ($n)"
ret=0
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.pre.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example in internal { type master; file "added.db"; };' 2> rndc.out.ns2.$n
grep "permission denied" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to delete a policy zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone 'policy in internal' 2> rndc.out.ns2.$n >&1
grep 'cannot be deleted' rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:ensure the configuration context is cleaned up correctly ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig > /dev/null 2>&1 || ret=1
sleep 5
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 status > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
