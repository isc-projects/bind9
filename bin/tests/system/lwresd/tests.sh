#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
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

# $Id: tests.sh,v 1.10 2000/11/20 17:53:29 gson Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

sleep 5

status=0

echo "I:using resolv.conf"
ret=0
./lwtest || ret=1
if [ $ret != 0 ]; then
	echo "I:failed"
fi
status=`expr $status + $ret`

kill -TERM `cat lwresd1/lwresd.pid` > /dev/null 2>&1
if [ $? != 0 ]; then
	echo "I:lwresd1 died before a SIGTERM was sent"
        status=1
        rm -f lwresd1/lwresd.pid
fi
sleep 6
if [ -f lwresd1/lwresd.pid ]; then
        echo "I:lwresd1 didn't die when sent a SIGTERM"
        kill -KILL `cat lwresd1/lwresd.pid` > /dev/null 2>&1
        if [ $? != 0 ]; then
                echo "I:lwresd1 died before a SIGKILL was sent"
                status=1
                rm -f lwresd1/lwresd.pid
        fi
        status=1
fi

(
	cd lwresd1
	$LWRESD -c lwresd.conf -d 99 -g >> lwresd.run 2>&1 &
	x=0
        while test ! -f lwresd.pid
        do
            x=`expr $x + 1`
            if [ $x = 5 ]; then
                echo "I:Couldn't start lwresd1"
                exit 1
            fi
            sleep 1
        done
)

echo "I:using lwresd.conf"
ret=0
./lwtest || ret=1
if [ $ret != 0 ]; then
	echo "I:failed"
fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
