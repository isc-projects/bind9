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

# $Id: tests.sh,v 1.26.4.1 2001/01/09 22:36:22 bwelling Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3 || status=1
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3 || status=1

rm -f ns2/example.db
cp ns2/example2.db ns2/example.db
sleep 6
kill -HUP `cat ns2/named.pid`
sleep 60

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3 || status=1
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3 || status=1

kill -TERM `cat ns3/named.pid` > /dev/null 2>&1
if [ $? != 0 ]; then
	echo "I:ns3 died before a SIGTERM was sent"
	status=1
	rm -f ns3/named.pid
fi
rm -f ns2/example.db
cp ns2/example3.db ns2/example.db
sleep 6

if [ -f ns3/named.pid ]; then
	echo "I:ns3 didn't die when sent a SIGTERM"
	kill -KILL `cat ns3/named.pid` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:ns3 died before a SIGKILL was sent"
		status=1
		rm -f ns3/named.pid
	fi
	status=1
fi

kill -HUP `cat ns2/named.pid`
(cd ns3 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 60

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3 || status=1
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3 || status=1

rm -f ns2/example.db
kill -TERM `cat ns2/named.pid` > /dev/null 2>&1
if [ $? != 0 ]; then
	echo "I:ns2 died before a SIGTERM was sent"
	status=1
	rm -f ns2/named.pid
fi
sleep 6

if [ -f ns2/named.pid ]; then
	echo "I:ns2 didn't die when sent a SIGTERM"
	kill -KILL `cat ns2/named.pid` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:ns2 died before a SIGKILL was sent"
		status=1
		rm -f ns2/named.pid
	fi
	status=1
fi

cp ns2/example4.db ns2/example.db
sleep 6
(cd ns2 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 60

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a -p 5300 > dig.out.ns2 || status=1
grep ";" dig.out.ns2

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a -p 5300 > dig.out.ns3 || status=1
grep ";" dig.out.ns3

$PERL ../digcomp.pl dig.out.ns2 dig.out.ns3 || status=1

echo "I:exit status: $status"
exit $status
