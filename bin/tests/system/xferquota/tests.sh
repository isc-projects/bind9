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
echo "T:system_xferquota:1"
echo "A:A test to determine online speed of domain name transfers"

#
# Perform tests
#

if [ -f dig.out.ns1 ]; then
	rm -f dig.out.ns1
fi
if [ -f dig.out.ns2 ]; then
	rm -f dig.out.ns2
fi

count=0
ticks=0
while [ $count != 100 ]; do
	sleep 5
	ticks=`expr $ticks + 1`
	seconds=`expr $ticks \* 5`
	if [ $ticks = 60 ]; then
		echo "Took too long to load domains."
		exit 1;
	fi
	count=`cat ns2/zone*.bk | grep xyzzy | wc -l`
	echo "I:Have $count domains up in $seconds seconds"
done

status=0;
../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	zone000099.example. @10.53.0.1 axfr > dig.out.ns1
status=`expr $status + $?`
grep ";" dig.out.ns1

../../../dig/dig +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
	zone000099.example. @10.53.0.2 axfr > dig.out.ns2
status=`expr $status + $?`
grep ";" dig.out.ns2

perl ../digcomp.pl dig.out.ns1 dig.out.ns2
status=`expr $status + $?`

if [ $status != 0 ]; then
	echo "R:FAIL"
else
	echo "R:PASS"
fi
