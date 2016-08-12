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
    echo "I:test with RT, single zone (+rec) ($n)"
    ret=0
    $DIG +rec -t RT rt.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with RT, two zones (+rec) ($n)"
    ret=0
    $DIG +rec -t RT rt.rt2.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, single zone (+rec) ($n)"
    ret=0
    $DIG +rec -t NAPTR nap.naptr.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, two zones (+rec) ($n)"
    ret=0
    $DIG +rec -t NAPTR nap.hang3b.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with LP (+rec) ($n)"
    ret=0
    $DIG +rec -t LP nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    case $minimal in
    no)
      grep -w "NS" dig.out.$n > /dev/null || ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    yes)
      grep -w "NS" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
      ;;
    no-auth)
      grep -w "NS" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    no-auth-recursive)
      grep -w "NS" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    esac
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID (+rec) ($n)"
    ret=0
    $DIG +rec -t NID ns1.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    else
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID + LP (+rec) ($n)"
    ret=0
    $DIG +rec -t NID nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep -w "LP" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    else
      grep -w "LP" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with RT, single zone (+norec) ($n)"
    ret=0
    $DIG +norec -t RT rt.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with RT, two zones (+norec) ($n)"
    ret=0
    $DIG +norec -t RT rt.rt2.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, single zone (+norec) ($n)"
    ret=0
    $DIG +norec -t NAPTR nap.naptr.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NAPTR, two zones (+norec) ($n)"
    ret=0
    $DIG +norec -t NAPTR nap.hang3b.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with LP (+norec) ($n)"
    ret=0
    $DIG +norec -t LP nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    case $minimal in
    no)
      grep -w "NS" dig.out.$n > /dev/null || ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    yes)
      grep -w "NS" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
      ;;
    no-auth)
      grep -w "NS" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    no-auth-recursive)
      grep -w "NS" dig.out.$n > /dev/null || ret=1
      grep -w "L64" dig.out.$n > /dev/null || ret=1
      grep -w "L32" dig.out.$n > /dev/null || ret=1
      ;;
    esac
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID (+norec) ($n)"
    ret=0
    $DIG +norec -t NID ns1.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    else
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    fi
    if [ $ret -eq 1 ] ; then
            echo "I: failed"; status=1
    fi

    n=`expr $n + 1`
    echo "I:test with NID + LP (+norec) ($n)"
    ret=0
    $DIG +norec -t NID nid2.nid.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
    if [ $minimal = no ] ; then
      # change && to || when we support NID additional processing
      grep -w "LP" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
    else
      grep -w "LP" dig.out.$n > /dev/null && ret=1
      grep -w "L64" dig.out.$n > /dev/null && ret=1
      grep -w "L32" dig.out.$n > /dev/null && ret=1
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

n=`expr $n + 1`
echo "I:testing with 'minimal-any no;' ($n)"
ret=0
$DIG -t ANY www.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "ANSWER: 3, AUTHORITY: 1, ADDITIONAL: 2" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

echo "I:reconfiguring server"
cp ns1/named3.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig 2>&1 | sed 's/^/I:ns1 /'
sleep 2

n=`expr $n + 1`
echo "I:testing with 'minimal-any yes;' ($n)"
ret=0
$DIG -t ANY www.rt.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

echo "I:testing with 'minimal-responses no-auth;'"
minimal=no-auth
dotests

echo "I:reconfiguring server"
cp ns1/named4.conf ns1/named.conf
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig 2>&1 | sed 's/^/I:ns1 /'
sleep 2

echo "I:testing with 'minimal-responses no-auth-recursive;'"
minimal=no-auth-recursive
dotests

n=`expr $n + 1`
echo "I:testing returning TLSA records with MX query ($n)"
ret=0
$DIG -t mx mx.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "mx\.example\..*MX.0 mail\.mx\.example" dig.out.$n > /dev/null || ret=1
grep "mail\.mx\.example\..*A.1\.2\.3\.4" dig.out.$n > /dev/null || ret=1
grep "_25\._tcp\.mail\.mx\.example\..*TLSA.3 0 1 5B30F9602297D558EB719162C225088184FAA32CA45E1ED15DE58A21 D9FCE383" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

n=`expr $n + 1`
echo "I:testing returning TLSA records with SRV query ($n)"
ret=0
$DIG -t srv _xmpp-client._tcp.srv.example @10.53.0.1 -p 5300 > dig.out.$n || ret=1
grep "_xmpp-client\._tcp\.srv\.example\..*SRV.1 0 5222 server\.srv\.example" dig.out.$n > /dev/null || ret=1
grep "server\.srv\.example\..*A.1\.2\.3\.4" dig.out.$n > /dev/null || ret=1
grep "_5222\._tcp\.server\.srv\.example\..*TLSA.3 0 1 5B30F9602297D558EB719162C225088184FAA32CA45E1ED15DE58A21 D9FCE383" dig.out.$n > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I: failed"; status=1
fi

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
