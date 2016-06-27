#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.19 2011/11/04 23:46:15 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

echo "I:1000 A records"
$DIG +tcp +norec 1000.example. @10.53.0.1 a -p 5300 > dig.out.1000 || status=1
#dig 1000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.1000
$PERL ../digcomp.pl knowngood.dig.out.1000 dig.out.1000 || status=1

echo "I:2000 A records"
$DIG +tcp +norec 2000.example. @10.53.0.1 a -p 5300 > dig.out.2000 || status=1
#dig 2000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.2000
$PERL ../digcomp.pl knowngood.dig.out.2000 dig.out.2000 || status=1

echo "I:3000 A records"
$DIG +tcp +norec 3000.example. @10.53.0.1 a -p 5300 > dig.out.3000 || status=1
#dig 3000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.3000
$PERL ../digcomp.pl knowngood.dig.out.3000 dig.out.3000 || status=1

echo "I:4000 A records"
$DIG +tcp +norec 4000.example. @10.53.0.1 a -p 5300 > dig.out.4000 || status=1
#dig 4000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.4000
$PERL ../digcomp.pl knowngood.dig.out.4000 dig.out.4000 || status=1

echo "I:exactly maximum rrset"
$DIG +tcp +norec +noedns a-maximum-rrset.example. @10.53.0.1 a -p 5300 > dig.out.a-maximum-rrset \
	|| status=1
#dig a-maximum-rrset.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.a-maximum-rrset
$PERL ../digcomp.pl knowngood.dig.out.a-maximum-rrset dig.out.a-maximum-rrset || status=1

echo "I:exceed maximum rrset (5000 A records)"
$DIG +tcp +norec +noadd 5000.example. @10.53.0.1 a -p 5300 > dig.out.exceed || status=1
# Look for truncation bit (tc).
grep 'flags: .*tc.*;' dig.out.exceed > /dev/null || {
    echo "I:TC bit was not set"
    status=1
}

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
