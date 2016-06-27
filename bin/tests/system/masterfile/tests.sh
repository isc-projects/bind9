#!/bin/sh
#
# Copyright (C) 2001, 2004, 2007, 2010, 2012, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.7 2010/09/15 12:38:35 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

ret=0
n=`expr $n + 1`
echo "I:test master file \$INCLUDE semantics ($n)"
$DIG +nostats +nocmd include. axfr @10.53.0.1 -p 5300 >dig.out.$n

echo "I:test master file BIND 8 compatibility TTL and \$TTL semantics ($n)"
$DIG +nostats +nocmd ttl2. axfr @10.53.0.1 -p 5300 >>dig.out.$n

echo "I:test of master file RFC1035 TTL and \$TTL semantics ($n)"
$DIG +nostats +nocmd ttl2. axfr @10.53.0.1 -p 5300 >>dig.out.$n

diff dig.out.$n knowngood.dig.out || status=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo "I:test that the nameserver is running with a missing master file ($n)"
$DIG +tcp +noall +answer example soa @10.53.0.2 -p 5300 > dig.out.$n 
grep SOA dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo "I:test that the nameserver returns SERVFAIL for a missing master file ($n)"
$DIG +tcp +all missing soa @10.53.0.2 -p 5300 > dig.out.$n 
grep "status: SERVFAIL" dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
n=`expr $n + 1`
echo "I:test owner inheritence after "'$INCLUDE'" ($n)"
$CHECKZONE -Dq example zone/inheritownerafterinclude.db > checkzone.out$n
diff checkzone.out$n zone/inheritownerafterinclude.good || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
