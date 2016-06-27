#!/bin/sh
#
# Copyright (C) 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.7 2011/11/06 23:46:40 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

dotests() {
    n=`expr $n + 1`
    echo "I:test with RT, single zone ($n)"
    ret=0
    $DIG -t RT rt.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with RT, two zones ($n)"
    ret=0
    $DIG -t RT rt.rt2.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, single zone ($n)"
    ret=0
    $DIG -t NAPTR nap.naptr.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, two zones ($n)"
    ret=0
    $DIG -t NAPTR nap.hang3b.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with LP ($n)"
    ret=0
    $DIG -t LP nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      grep "L64" dig.out.$n > /dev/null || ret=1
      grep "L32" dig.out.$n > /dev/null || ret=1
    else
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID ($n)"
    ret=0
    $DIG -t NID ns1.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    else
      grep "L64" dig.out.$n > /dev/null && ret=1
      grep "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID + LP ($n)"
    ret=0
    $DIG -t NID nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
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
            echo "I: failed"; status=1
    fi
}

echo "I:testing with 'minimal-responses yes;'"
minimal=yes
dotests

echo "I:reconfiguring server"
cp ns1/named2.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig 2>&1 | sed 's/^/I:ns1 /'
sleep 2

echo "I:testing with 'minimal-responses no;'"
minimal=no
dotests

echo "I:testing with 'minimal-any no;'"
n=`expr $n + 1`
$DIG -t ANY www.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "ANSWER: 3, AUTHORITY: 1, ADDITIONAL: 2" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

echo "I:reconfiguring server"
cp ns1/named3.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig 2>&1 | sed 's/^/I:ns1 /'
sleep 2

echo "I:testing with 'minimal-any yes;'"
n=`expr $n + 1`
$DIG -t ANY www.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
