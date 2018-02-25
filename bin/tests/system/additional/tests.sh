#!/bin/sh
#
# Copyright (C) 2013, 2016-2018  Internet Systems Consortium, Inc. ("ISC")
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

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

dotests() {
    n=`expr $n + 1`
    echo_i "test with RT, single zone ($n)"
    ret=0
    $DIG $DIGOPTS -t RT rt.rt.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with RT, two zones ($n)"
    ret=0
    $DIG $DIGOPTS -t RT rt.rt2.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with NAPTR, single zone ($n)"
    ret=0
    $DIG $DIGOPTS -t NAPTR nap.naptr.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with NAPTR, two zones ($n)"
    ret=0
    $DIG $DIGOPTS -t NAPTR nap.hang3b.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with LP ($n)"
    ret=0
    $DIG $DIGOPTS -t LP nid2.nid.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      grep "L64" dig.out.$n > /dev/null || ret=1
      grep "L32" dig.out.$n > /dev/null || ret=1
    else
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with NID ($n)"
    ret=0
    $DIG $DIGOPTS -t NID ns1.nid.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    else
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi

    n=`expr $n + 1`
    echo_i "test with NID + LP ($n)"
    ret=0
    $DIG $DIGOPTS -t NID nid2.nid.example @10.53.0.1 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep "LP" dig.out.$n > /dev/null && ret=1
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    else
      grep "LP" dig.out.$n > /dev/null && ret=1
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo_i " failed"; status=1
    fi
}

echo_i "testing with 'minimal-responses yes;'"
minimal=yes
dotests

echo_i "reconfiguring server: minimal-responses no"
copy_setports ns1/named2.conf.in ns1/named.conf
$RNDCCMD 10.53.0.1 reconfig 2>&1 | sed 's/^/ns1 /' | cat_i
sleep 2

echo_i "testing with 'minimal-responses no;'"
minimal=no
dotests

n=`expr $n + 1`
echo_i "testing NS handling in ANY responses (authoritative) ($n)"
ret=0
$DIG $DIGOPTS -t ANY rt.example @10.53.0.1 > dig.out.$n || ret=1
grep "AUTHORITY: 0" dig.out.$n  > /dev/null || ret=1
grep "NS[ 	]*ns" dig.out.$n  > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo_i " failed"; status=1
fi

n=`expr $n + 1`
echo_i "testing NS handling in ANY responses (recursive) ($n)"
ret=0
$DIG $DIGOPTS -t ANY rt.example @10.53.0.3 > dig.out.$n || ret=1
grep "AUTHORITY: 0" dig.out.$n  > /dev/null || ret=1
grep "NS[ 	]*ns" dig.out.$n  > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo_i " failed"; status=1
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
