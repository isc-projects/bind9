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

#
# Perform tests
#

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

rm -f dig.out.*

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd -p 5300"

# Check the example. domain
$DIG $DIGOPTS \
	a.example. @10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG $DIGOPTS \
	a.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f dig.out.*

$DIG $DIGOPTS +noauth \
	a.example. @10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG $DIGOPTS +noauth \
	a.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns2

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns4
status=`expr $status + $?`

# Check the insecure.example domain

rm -f dig.out.*

$DIG $DIGOPTS \
	a.insecure.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$DIG $DIGOPTS \
	a.insecure.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

$PERL ../digcomp.pl dig.out.ns3 dig.out.ns4
status=`expr $status + $?`

# Check the secure.example domain

rm -f dig.out.*

$DIG $DIGOPTS \
	a.secure.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$DIG $DIGOPTS \
	a.secure.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

$PERL ../digcomp.pl dig.out.ns3 dig.out.ns4
status=`expr $status + $?`

# Check the bogus domain

rm -f dig.out.*

$DIG +tcp +noadd +nosea +nostat +noquest +nocmd -p 5300 \
	a.bogus.example. @10.53.0.4 a > dig.out.ns4
grep "SERVFAIL" dig.out.ns4 > /dev/null
status=`expr $status + $?`
echo "SERVFAIL is expected in the following:"
grep ";" dig.out.ns4

if [ $status != 0 ]; then
	echo "R:FAIL"
else
	echo "R:PASS"
fi

