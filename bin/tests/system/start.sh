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

# $Id: start.sh,v 1.21.2.1 2000/06/26 21:21:18 gson Exp $

#
# Start name servers for running system tests.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

test $# -gt 0 || { echo "usage: $0 test-directory" >&2; exit 1; }

test -d "$1" || { echo No test directory: "$1";  exit 1; }

if $PERL ./testsock.pl -p 5300
then
    :
else
    echo "$0: could not bind to server addresses, server still running?"
    echo "I:server sockets not available"
    echo "R:FAIL"
    sh ./stop.sh $1
    exit 1
fi 

cd $1

for d in ns*
do
    (
        cd $d
	rm -f *.jnl *.bk *.st named.run
	$NAMED -c named.conf -d 99 -g >named.run 2>&1 &
	x=1
	while test ! -f named.pid
	do
	    x=`expr $x + 1`
	    if [ $x = 15 ]; then
		echo "I:Couldn't start server $d"
   	        echo "R:FAIL"
		cd ../..
		sh ./stop.sh $1
		exit 1
	    fi
	    sleep 1
        done
    ) || exit 1
done

for d in lwresd*
do
    (
	if test ! -d $d
	then
		break
	fi
        cd $d
	rm -f lwresd.run &&
	if test -f lwresd.pid
	then
	    if kill -0 `cat lwresd.pid` 2>/dev/null
	    then
		echo "$0: lwresd pid `cat lwresd.pid` still running" >&2
	        exit 1
	    else
		rm -f lwresd.pid
	    fi
	fi
	$LWRESD -C resolv.conf -d 99 -g -i lwresd.pid -p 9210 -P 5300 > lwresd.run 2>&1 &
	x=1
	while test ! -f lwresd.pid
	do
	    x=`expr $x + 1`
	    if [ $x = 5 ]; then
		echo "I: Couldn't start lwresd $d"
		exit 1
	    fi
	    sleep 1
        done
    ) || exit 1
done

# Make sure all of the servers are up.

status=0

sleep 5

for d in ns*
do
	try=0
	while true
	do
		n=`echo $d | sed 's/ns//'`
		if $DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd \
			-p 5300 version.bind. chaos txt @10.53.0.$n > dig.out
		then
			break
		fi
		grep ";" dig.out
		try=`expr $try + 1`
		if [ $try = 30 ]; then
			cd ..
			sh ./stop.sh $1
			echo "I: no response from $d"
			echo "R:FAIL"
			exit 1
		fi
		sleep 9
	done
done
rm -f dig.out

