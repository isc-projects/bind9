#!/bin/sh
#
# Perform tests
#

TOP="`cd ../../../..; pwd`"

NAMED=$TOP/bin/named/named
export NAMED

rm -f dig.out.ns2* dig.out.ns3* 2>&1 > /dev/null

status=0;
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth\
	a.example. @10.53.0.2 any > dig.out.ns2.1
status=`expr $status + $?`
grep ";" dig.out.ns2.1

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth\
	a.example. @10.53.0.3 any > dig.out.ns3.1
status=`expr $status + $?`
grep ";" dig.out.ns3.1

rm -f ns2/named.conf ns3/named.conf ns2/example.db
cp ns2/named2.conf ns2/named.conf
cp ns3/named2.conf ns3/named.conf
cp ns2/example2.db ns2/example.db
kill -HUP `cat ns2/named.pid`
kill -HUP `cat ns3/named.pid`
sleep 10

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth\
	-b 10.53.0.4 a.example. @10.53.0.4 any > dig.out.ns4.2
status=`expr $status + $?`
grep ";" dig.out.ns4.2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth\
	-b 10.53.0.2 a.example. @10.53.0.2 any > dig.out.ns2.2
status=`expr $status + $?`
grep ";" dig.out.ns2.2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd +noauth\
	@10.53.0.3 a.example. any > dig.out.ns3.2
status=`expr $status + $?`
grep ";" dig.out.ns3.2

perl ../digcomp.pl dig.out.ns2.1 dig.out.ns4.2
status=`expr $status + $?`

perl ../digcomp.pl dig.out.ns3.1 dig.out.ns2.2
status=`expr $status + $?`

perl ../digcomp.pl dig.out.ns3.1 dig.out.ns3.2
status=`expr $status + $?`

echo "Differences should be found in the following lines:"
perl ../digcomp.pl dig.out.ns2.1 dig.out.ns3.2
if [ $? = 0 ]; then
	echo "No differences found.  Something's wrong."
	$status=`expr $status + 1`
fi

if [ $status != 0 ]; then
	echo "FAILED with status $status"
fi

exit $status
