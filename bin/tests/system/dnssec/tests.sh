#!/bin/sh
#
# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: tests.sh,v 1.27.4.2 2001/01/09 22:35:04 bwelling Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocmd +dnssec -p 5300"

# Check the example. domain

echo "I:checking that zone transfer worked ($n)"
ret=0
$DIG $DIGOPTS a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS a.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns3.test$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking positive validation ($n)"
ret=0
$DIG $DIGOPTS +noauth a.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS +noauth a.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking negative validation ($n)"
ret=0
$DIG $DIGOPTS +noauth q.example. @10.53.0.2 a > dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS +noauth q.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the insecure.example domain

echo "I:checking 1-server insecurity proof ($n)"
ret=0
$DIG $DIGOPTS a.insecure.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$DIG $DIGOPTS a.insecure.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the secure.example domain

echo "I:checking multi-stage positive validation ($n)"
ret=0
$DIG $DIGOPTS +noauth a.secure.example. @10.53.0.3 a > dig.out.ns3.test$n || ret=1
$DIG $DIGOPTS +noauth a.secure.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns3.test$n dig.out.ns4.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the bogus domain

echo "I:checking failed validation ($n)"
ret=0
$DIG $DIGOPTS a.bogus.example. @10.53.0.4 a > dig.out.ns4.test$n || ret=1
grep "SERVFAIL" dig.out.ns4.test$n > /dev/null > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Try validating with a bad trusted key.
# This should fail.

echo "I:checking that validation fails with a misconfigured trusted key ($n)"
ret=0
$DIG $DIGOPTS example. soa @10.53.0.5 > dig.out.ns5.test$n || ret=1
grep "SERVFAIL" dig.out.ns5.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check the insecure.secure.example domain (insecurity proof)

echo "I:checking 2-server insecurity proof ($n)"
ret=0
$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.2 a \
	> dig.out.ns2.test$n || ret=1
$DIG $DIGOPTS a.insecure.secure.example. @10.53.0.4 a \
	> dig.out.ns4.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check a negative response in insecure.secure.example

echo "I:checking 2-server insecurity proof with a negative answer ($n)"
ret=0
$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.2 a > dig.out.ns2.test$n \
	|| ret=1
$DIG $DIGOPTS q.insecure.secure.example. @10.53.0.4 a > dig.out.ns4.test$n \
	|| ret=1
$PERL ../digcomp.pl dig.out.ns2.test$n dig.out.ns4.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check that the query for a security root is successful and has ad set

echo "I:checking security root query ($n)"
ret=0
$DIG $DIGOPTS . @10.53.0.4 key > dig.out.ns4.test$n || ret=1
grep "NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

# Check that the setting the cd bit works

echo "I:checking cd bit on a positive answer ($n)"
ret=0
$DIG $DIGOPTS +noauth example. soa @10.53.0.4 \
	> dig.out.ns4.test$n || ret=1
$DIG $DIGOPTS +noauth +cdflag example. soa @10.53.0.5 \
	> dig.out.ns5.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns4.test$n dig.out.ns5.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking cd bit on a negative answer ($n)"
ret=0
$DIG $DIGOPTS q.example. soa @10.53.0.4 > dig.out.ns4.test$n || ret=1
$DIG $DIGOPTS +cdflag q.example. soa @10.53.0.5 > dig.out.ns5.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns4.test$n dig.out.ns5.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking cd bit on a query that should fail ($n)"
ret=0
$DIG $DIGOPTS a.bogus.example. soa @10.53.0.4 \
	> dig.out.ns4.test$n || ret=1
$DIG $DIGOPTS +cdflag a.bogus.example. soa @10.53.0.5 \
	> dig.out.ns5.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns4.test$n dig.out.ns5.test$n || ret=1
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null || ret=1
# Note - this is looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking cd bit on an insecurity proof ($n)"
ret=0
$DIG $DIGOPTS +noauth a.insecure.example. soa @10.53.0.4 \
	> dig.out.ns4.test$n || ret=1
$DIG $DIGOPTS +noauth +cdflag a.insecure.example. soa @10.53.0.5 \
	> dig.out.ns5.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns4.test$n dig.out.ns5.test$n || ret=1
grep "status: NOERROR" dig.out.ns4.test$n > /dev/null || ret=1
# Note - these are looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null && ret=1
grep "flags:.*ad.*QUERY" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking cd bit on a negative insecurity proof ($n)"
ret=0
$DIG $DIGOPTS q.insecure.example. soa @10.53.0.4 \
	> dig.out.ns4.test$n || ret=1
$DIG $DIGOPTS +cdflag q.insecure.example. soa @10.53.0.5 \
	> dig.out.ns5.test$n || ret=1
$PERL ../digcomp.pl dig.out.ns4.test$n dig.out.ns5.test$n || ret=1
grep "status: NXDOMAIN" dig.out.ns4.test$n > /dev/null || ret=1
# Note - these are looking for failure, hence the &&
grep "flags:.*ad.*QUERY" dig.out.ns4.test$n > /dev/null && ret=1
grep "flags:.*ad.*QUERY" dig.out.ns5.test$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
