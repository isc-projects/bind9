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

# $Id: stop.sh,v 1.16 2000/08/01 01:14:29 tale Exp $

#
# Stop name servers.
#

test $# -gt 0 || { echo "usage: $0 test-directory" >&2; exit 1; }

status=0

cd $1

for d in ns*
do
     pidfile="$d/named.pid"
     if [ -f $pidfile ]; then
        kill -TERM `cat $pidfile` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:$d died before a SIGTERM was sent"
		status=`expr $status + 1`
		rm -f $pidfile
	fi
     fi
done

for d in lwresd*
do
     pidfile="$d/lwresd.pid"
     if [ -f $pidfile ]; then
        kill -TERM `cat $pidfile` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:$d died before a SIGTERM was sent"
		status=`expr $status + 1`
		rm -f $pidfile
	fi
     fi
done

for d in ans*
do
     pidfile="$d/ans.pid"
     if [ -f $pidfile ]; then
        kill -TERM `cat $pidfile` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:$d died before a SIGTERM was sent"
		status=`expr $status + 1`
		rm -f $pidfile
	fi
     fi
done

sleep 5

for d in ns*
do
     pidfile="$d/named.pid"
     if [ -f $pidfile ]; then
	echo "I:$d didn't die when sent a SIGTERM"
	status=`expr $status + 1`
        kill -KILL `cat $pidfile` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:$d died before a SIGKILL was sent"
		status=`expr $status + 1`
		rm -f $pidfile
	fi
        rm -f $pidfile
     fi
done

for d in lwresd*
do
     pidfile="$d/lwresd.pid"
     if [ -f $pidfile ]; then
	echo "I:$d didn't die when sent a SIGTERM"
	status=`expr $status + 1`
        kill -KILL `cat $pidfile` > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "I:$d died before a SIGKILL was sent"
		status=`expr $status + 1`
		rm -f $pidfile
	fi
        rm -f $pidfile
     fi
done

exit $status
