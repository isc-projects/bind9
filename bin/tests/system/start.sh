#!/bin/sh
#
# Start name servers for running system tests.
#


. ./conf.sh
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
	while test ! -f named.pid
	do
	    sleep 1
        done
    )
done

