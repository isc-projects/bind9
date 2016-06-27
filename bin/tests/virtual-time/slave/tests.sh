#!/bin/sh
#
# Copyright (C) 2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.2 2010/06/17 05:38:06 marka Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +nocmd -p 5300"

echo "I:checking slave expiry"
ret=0
$DIG $DIGOPTS txt.example. txt @10.53.0.1 > dig.out.before || ret=1
echo "I:waiting for expiry (10s real, 6h virtual)"
sleep 10
$DIG $DIGOPTS txt.example. txt @10.53.0.1 > dig.out.after || ret=1
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
grep "status: NOERROR" dig.out.before > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I:failed (before)"; status=1
fi
ret=0
grep "status: SERVFAIL" dig.out.after > /dev/null || ret=1
if [ $ret -eq 1 ] ; then
    echo "I:failed (after)"; status=1
fi

echo "I:exit status: $status"
exit $status
