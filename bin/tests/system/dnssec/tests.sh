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

# $Id: tests.sh,v 1.18 2000/07/08 00:39:17 bwelling Exp $

#
# Perform tests
#

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocmd -p 5300"

# Check the example. domain
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || status=1
$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || status=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns3.test$n || status=1
n=`expr $n + 1`

$DIG $DIGOPTS +noauth a.example. @10.53.0.2 a > dig.out.ns2.test$n || status=1
$DIG $DIGOPTS +noauth a.example. @10.53.0.4 a > dig.out.ns4.test$n || status=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || status=1
n=`expr $n + 1`

# Check the insecure.example domain

$DIG $DIGOPTS a.insecure.example. @10.53.0.3 a > dig.out.ns3.test$n || status=1
$DIG $DIGOPTS a.insecure.example. @10.53.0.4 a > dig.out.ns4.test$n || status=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || status=1
n=`expr $n + 1`

# Check the secure.example domain

$DIG $DIGOPTS a.secure.example. @10.53.0.3 a > dig.out.ns3.test$n || status=1
$DIG $DIGOPTS a.secure.example. @10.53.0.4 a > dig.out.ns4.test$n || status=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || status=1
n=`expr $n + 1`

# Check the bogus domain

$DIG +tcp +noadd +nosea +nostat +noquest +nocmd -p 5300 \
	a.bogus.example. @10.53.0.4 a > dig.out.ns4.test$n || status=1
grep "SERVFAIL" dig.out.ns4.test$n > /dev/null || status=1

n=`expr $n + 1`

# Try validating a key with a bad trusted key.
# This should fail.

$DIG +tcp +noadd +nosea +nostat +noquest +nocmd -p 5300 \
    example. key @10.53.0.5 -p 5300 > dig.out.ns5.test$n || status=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || status=1

n=`expr $n + 1`

# Check the insecure.secure.example domain (insecurity proof)

$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.2 a > dig.out.ns2.test$n \
	|| status=1
$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.4 a > dig.out.ns4.test$n \
	|| status=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || status=1
n=`expr $n + 1`

# Check a negative response in insecure.secure.example

$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.2 a > dig.out.ns2.test$n \
	|| status=1
$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.4 a > dig.out.ns4.test$n \
	|| status=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || status=1
n=`expr $n + 1`

echo "I:exit status: $status"
exit $status
