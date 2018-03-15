#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noauth +noadd +nostats +dnssec -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

echo_i "checking normally loaded zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking previously added zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding new zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'added.example { type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding a zone that requires quotes ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"32/1.0.0.127-in-addr.added.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.32/1.0.0.127-in-addr.added.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.32/1.0.0.127-in-addr.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding a zone with a quote in the name ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"foo\"bar.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.foo\\"bar.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding new zone with missing master file ($n)"
ret=0
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.pre.$n || ret=1
grep "status: REFUSED" dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 addzone 'missing.example { type master; file "missing.db"; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.post.$n || ret=1
grep "status: REFUSED" dig.out.ns2.post.$n > /dev/null || ret=1
digcomp dig.out.ns2.pre.$n dig.out.ns2.post.$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "verifying no comments in nzf file ($n)"
ret=0
hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
[ $hcount -eq 0 ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting previously added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone previous.example 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking nzf file now has comment ($n)"
ret=0
hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
[ $hcount -eq 1 ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting newly added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone added.example 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting newly added zone with escaped quote ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone "foo\\\"bar.example" 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep "^a.foo\"bar.example" dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempt to delete a normally-loaded zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone normal.example 2> rndc.out.ns2.$n
grep "permission denied" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add master zone with inline signing ($n)"
$RNDCCMD 10.53.0.2 addzone 'inline.example { type master; file "inline.db"; inline-signing yes; };' 2>&1 | sed 's/^/ns2 /' | cat_i
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
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add master zone with inline signing and missing master ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'inlinemissing.example { type master; file "missing.db"; inline-signing yes; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add slave zone with inline signing ($n)"
$RNDCCMD 10.53.0.2 addzone 'inlineslave.example { type slave; masters { 10.53.0.1; }; file "inlineslave.bk"; inline-signing yes; };' 2>&1 | sed 's/^/ns2 /' | cat_i
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
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that adding a 'stub' zone works ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'stub.example { type stub; masters { 1.2.3.4; }; file "stub.example.bk"; };' > rndc.out.ns2.$n 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that adding a 'static-stub' zone works ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'static-stub.example { type static-stub; server-addresses { 1.2.3.4; }; };' > rndc.out.ns2.$n 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'redirect' (master) is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type redirect; file "redirect.db"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'redirect' (slave) is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type redirect; masters { 1.2.3.4; }; file "redirect.bk"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'hint' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type hint; file "hints.db"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'forward' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'forward.example { type forward; forwarders { 1.2.3.4; }; forward only; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'delegation-only' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'delegation-only.example { type delegation-only; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "reconfiguring server with multiple views"
rm -f ns2/named.conf 
copy_setports ns2/named2.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reconfig 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 5

echo_i "adding new zone to external view ($n)"
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
$RNDCCMD 10.53.0.2 addzone 'added.example in external { type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking new nzf file has comment ($n)"
ret=0
hcount=`grep "^# New zone file for view: external" ns2/3c4623849a49a539.nzf | wc -l`
[ $hcount -eq 1 ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking rndc reload causes named to reload the external view's NZF file ($n)"
ret=0
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting newly added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone 'added.example in external' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add zone to internal view ($n)"
ret=0
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.pre.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 addzone 'added.example in internal { type master; file "added.db"; };' 2> rndc.out.ns2.$n
grep "permission denied" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to delete a policy zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone 'policy in internal' 2> rndc.out.ns2.$n >&1
grep 'cannot be deleted' rndc.out.ns2.$n > /dev/null ||
grep 'permission denied' rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "ensure the configuration context is cleaned up correctly ($n)"
ret=0
$RNDCCMD 10.53.0.2 reconfig > /dev/null 2>&1 || ret=1
sleep 5
$RNDCCMD 10.53.0.2 status > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check delzone after reconfig failure ($n)"
ret=0
$RNDCCMD 10.53.0.3 addzone 'inlineslave.example. IN { type slave; file "inlineslave.db"; masterfile-format text; masters { testmaster; }; };' > /dev/null 2>&1 || ret=1
copy_setports ns3/named2.conf.in ns3/named.conf
$RNDCCMD 10.53.0.3 reconfig > /dev/null 2>&1 && ret=1
sleep 5
$RNDCCMD 10.53.0.3 delzone inlineslave.example > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
