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

echo "S:`date`"
echo "T:system_dnssec:1"
echo "A:A test to determine online functionality of dnssec tools"

#
# Perform tests
#

if [ -f dig.out.ns2 ]; then
	rm -f dig.out.ns2
fi
if [ -f dig.out.ns3 ]; then
	rm -f dig.out.ns3
fi
if [ -f dig.out.ns4 ]; then
	rm -f dig.out.ns4
fi

# Make sure all of the servers are up
status=0;
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd . \
	@10.53.0.2 soa > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd . \
	@10.53.0.3 soa > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd . \
	@10.53.0.4 soa > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

rm -f dig.out.*

# Check the example. domain
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.example. @10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f dig.out.*

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth \
	a.example. @10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth \
	a.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns2

perl ../digcomp.pl dig.out.ns2 dig.out.ns4
status=`expr $status + $?`

# Check the insecure.example domain

rm -f dig.out.*

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.insecure.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.insecure.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

perl ../digcomp.pl dig.out.ns3 dig.out.ns4
status=`expr $status + $?`

# Check the secure.example domain

rm -f dig.out.*

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.secure.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.secure.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

perl ../digcomp.pl dig.out.ns3 dig.out.ns4
status=`expr $status + $?`

# Check the bogus domain

rm -f dig.out.*

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocmd \
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

