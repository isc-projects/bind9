#!/bin/sh
#
# Perform tests
#

TOP="`cd ../../../..; pwd`"

NAMED=$TOP/bin/named/named
export NAMED

if [ -f dig.out.ns2 ]; then
	rm -f dig.out.ns2
fi
if [ -f dig.out.ns3 ]; then
	rm -f dig.out.ns3
fi

status=0;
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f ns2/a.example.db
cp ns2/example2.db ns2/a.example.db
kill -HUP `cat ns2/named.pid`
sleep 30

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

kill `cat ns3/named.pid`
rm -f ns2/a.example.db
cp ns2/example3.db ns2/a.example.db
kill -HUP `cat ns2/named.pid`
(cd ns3 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 30

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

rm -f ns2/a.example.db
kill `cat ns2/named.pid`
cp ns2/example4.db ns2/a.example.db
(cd ns2 ; $NAMED -c named.conf -d 99 -g >> named.run 2>&1 & )
sleep 30

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd a.example.\
	@10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
status=`expr $status + $?`

if [ $status != 0 ]; then
	echo "FAILED with status $status"
fi

exit $status
