#!/bin/sh
#
# Stop name servers.
#

cd $1

for d in ns*
do
     pidfile="$d/named.pid"
     if [ -f $pidfile ]; then
        kill -TERM `cat $pidfile`
     fi
done

sleep 5

for d in ns*
do
     pidfile="$d/named.pid"
     if [ -f $pidfile ]; then
        kill -KILL `cat $pidfile`
     fi
done
