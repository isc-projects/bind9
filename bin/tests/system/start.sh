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
# Start name servers for running system tests.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

test $# -gt 0 || { echo "usage: $0 test-directory" >&2; exit 1; }

cd $1

for d in ns*
do
    (
        cd $d
	rm -f *.jnl *.bk named.run &&
	if test -f named.pid
	then
	    if kill -0 `cat named.pid` 2>/dev/null
	    then
		echo "$0: named pid `cat named.pid` still running" >&2
	        exit 1
	    else
		rm -f named.pid
	    fi
	fi
	$NAMED -c named.conf -d 99 -g >named.run 2>&1 &
	x=1
	while test ! -f named.pid
	do
	    x=`expr $x + 1`
	    if [ $x = 5 ]; then
		echo "I: Couldn't start server $d!"
		exit 1
	    fi
	    sleep 1
        done
    )
done


# Make sure all of the servers are up.

status=0

sleep 5

for d in ns*
do
	n=`echo $d | sed 's/ns//'`
	$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd -p 5300 \
		version.bind. chaos txt @10.53.0.$n > dig.out
	status=`expr $status + $?`
	grep ";" dig.out
done
rm -f dig.out

if [ $status != 0 ]
then
    echo "I: Couldn't talk to server(s)."
    cd ..
    sh stop.sh $1
fi

exit $status
