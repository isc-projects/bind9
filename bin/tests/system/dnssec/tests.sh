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

# $Id: tests.sh,v 1.19 2000/07/10 21:40:16 bwelling Exp $

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
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns3.test$n || ret=1
n=`expr $n + 1`
echo "I:checking that zone transfer worked"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

ret=0
$DIG $DIGOPTS +noauth a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS +noauth a.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
n=`expr $n + 1`
echo "I:checking positive validation"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the insecure.example domain

ret=0
$DIG $DIGOPTS a.insecure.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$DIG $DIGOPTS a.insecure.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || ret=1
n=`expr $n + 1`
echo "I:checking 1-server insecurity proof"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the secure.example domain

ret=0
$DIG $DIGOPTS a.secure.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$DIG $DIGOPTS a.secure.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || ret=1
n=`expr $n + 1`
echo "I:checking multi-stage positive validation"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the bogus domain

ret=0
$DIG $DIGOPTS a.bogus.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
grep "SERVFAIL" dig.out.ns4.test$n > /dev/null || ret=1
n=`expr $n + 1`
echo "I:checking negative validation"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Try validating a key with a bad trusted key.
# This should fail.

ret=0
$DIG $DIGOPTS example. key @10.53.0.5 -p 5300 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
echo "I:checking that validation fails with a misconfigured trusted key"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the insecure.secure.example domain (insecurity proof)

ret=0
$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.2 a > dig.out.ns2.test$n \
	|| ret=1
$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.4 a > dig.out.ns4.test$n \
	|| ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
n=`expr $n + 1`
echo "I:checking 2-server insecurity proof"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check a negative response in insecure.secure.example

ret=0
$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.2 a > dig.out.ns2.test$n \
	|| ret=1
$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.4 a > dig.out.ns4.test$n \
	|| ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
n=`expr $n + 1`
echo "I:checking 2-server insecurity proof with a negative answer"
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
