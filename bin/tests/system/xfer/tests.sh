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


status=0;
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example. \
	@10.53.0.2 axfr > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example. \
	@10.53.0.3 axfr > dig.out.ns3
status=`expr $status + $?`
grep ";" dig.out.ns3

perl ../digcomp.pl knowngood.dig.out dig.out.ns2
status=`expr $status + $?`

perl ../digcomp.pl knowngood.dig.out dig.out.ns3
status=`expr $status + $?`
