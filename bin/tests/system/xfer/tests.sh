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

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Perform tests
#

sleep 5

status=0;
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example. \
	@10.53.0.2 axfr -p 5300 > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example. \
	@10.53.0.3 axfr -p 5300 > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl knowngood.dig.out dig.out.ns2
status=`expr $status + $?`

$PERL ../digcomp.pl knowngood.dig.out dig.out.ns3
status=`expr $status + $?`

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	tsigzone. @10.53.0.2 axfr -y tsigzone.:1234abcd8765 -p 5300 \
	> dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	tsigzone. @10.53.0.3 axfr -y tsigzone.:1234abcd8765 -p 5300 \
	> dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

if [ $status != 0 ]; then
	echo "R:FAIL"
else
	echo "R:PASS"
fi
