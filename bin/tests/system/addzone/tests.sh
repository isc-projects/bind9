#!/bin/sh
#
# Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.2.2.2 2010/08/11 18:19:55 each Exp $

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

echo "I:checking previously added zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:adding new zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting previously added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone previous.example 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting newly added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone added.example 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempt to delete a normally-loaded zone (should fail) ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone normal.example 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:reconfiguring server with multiple views"
rm -f ns2/named.conf 
cp -f ns2/named2.conf ns2/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 reconfig 2>&1 | sed 's/^/I:ns2 /'
sleep 5

echo "I:adding new zone to external view ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example in external { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.int.$n > /dev/null || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:deleting newly added zone ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 delzone 'added.example in external' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:attempting to add zone to internal view (should fail) ($n)"
ret=0
$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p 9953 addzone 'added.example in internal { type master; file "added.db"; };' 2>&1 | sed 's/^/I:ns2 /'
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
