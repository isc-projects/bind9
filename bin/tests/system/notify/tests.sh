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
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f ns2/example.db
cp ns2/example2.db ns2/example.db
sleep 6
kill -HUP `cat ns2/named.pid`
sleep 6

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

kill `cat ns3/named.pid`
rm -f ns2/example.db
cp ns2/example3.db ns2/example.db
sleep 6
kill -HUP `cat ns2/named.pid`
(cd ns3 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 6

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f ns2/example.db
kill `cat ns2/named.pid`
cp ns2/example4.db ns2/example.db
sleep 6
(cd ns2 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 6

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

if [ $status != 0 ]; then
	echo "R:FAIL"
else
	echo "R:PASS"
fi
