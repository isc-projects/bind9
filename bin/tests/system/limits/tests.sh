#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
# CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

# $Id: tests.sh,v 1.2.2.1 2000/06/28 19:33:17 gson Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Perform tests
#

# sleep 5

status=0;

$DIG +tcp +nosea +nostat +noquest +nocomm +nocmd +norec \
	1000.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
#dig 1000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.1000
$PERL ../digcomp.pl knowngood.dig.out.1000 dig.out.ns1
status=`expr $status + $?`

$DIG +tcp +nosea +nostat +noquest +nocomm +nocmd +norec \
	2000.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
#dig 2000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.2000
$PERL ../digcomp.pl knowngood.dig.out.2000 dig.out.ns1
status=`expr $status + $?`

$DIG +tcp +nosea +nostat +noquest +nocomm +nocmd +norec \
	3000.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
#dig 3000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.3000
$PERL ../digcomp.pl knowngood.dig.out.3000 dig.out.ns1
status=`expr $status + $?`

$DIG +tcp +nosea +nostat +noquest +nocomm +nocmd +norec \
	4000.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
#dig 4000.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.4000
$PERL ../digcomp.pl knowngood.dig.out.4000 dig.out.ns1
status=`expr $status + $?`

$DIG +tcp +nosea +nostat +noquest +nocomm +nocmd +norec \
	a-maximum-rrset.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
#dig a-maximum-rrset.example. @10.53.0.1 a -p 5300 > knowngood.dig.out.a-maximum-rrset
$PERL ../digcomp.pl knowngood.dig.out.a-maximum-rrset dig.out.ns1
status=`expr $status + $?`

$DIG +tcp +nosea +nostat +noquest +nocmd +norec \
	5000.example. @10.53.0.1 a -p 5300 > dig.out.ns1
status=`expr $status + $?`
grep 'flags: qr aa tc ad;' dig.out.ns1
status=`expr $status + $?`

if [ $status != 0 ]; then
	echo "R:FAIL"
else
	echo "R:PASS"
fi
