#!/bin/sh
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

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
perl ../digcomp.pl dig.out.ns2 dig.out.ns4

# Check the example. domain
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.example. @10.53.0.2 a > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.example. @10.53.0.3 a > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	a.example. @10.53.0.4 a > dig.out.ns4
status=`expr $status + $?`
grep ";" dig.out.ns4

perl ../digcomp.pl dig.out.ns2 dig.out.ns3
perl ../digcomp.pl dig.out.ns2 dig.out.ns4
